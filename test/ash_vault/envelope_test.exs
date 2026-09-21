defmodule AshVault.EnvelopeTest do
  use ExUnit.Case, async: true

  alias AshVault.Envelope
  alias AshVault.Envelope.V1
  alias AshVault.Errors.InvalidCiphertext
  alias AshVault.Errors.UnsupportedEnvelope

  defp sample(overrides \\ %{}) do
    Map.merge(
      %{
        version: 1,
        cipher: :aes_256_gcm_v1,
        key_version: 1,
        nonce: :crypto.strong_rand_bytes(12),
        tag: :crypto.strong_rand_bytes(16),
        ciphertext: "ciphertext"
      },
      overrides
    )
  end

  describe "encode/1 and decode/1 roundtrip" do
    test "a typical envelope" do
      env = sample()
      blob = V1.encode(env)

      assert <<"AV", 1, _::binary>> = blob
      assert {:ok, decoded} = Envelope.decode(blob)

      assert decoded == %{
               version: 1,
               cipher: "aes_256_gcm_v1",
               key_version: env.key_version,
               nonce: env.nonce,
               tag: env.tag,
               ciphertext: env.ciphertext
             }
    end

    test "the cipher id may be given as an atom or a binary and is stored as a binary" do
      from_atom = V1.encode(sample(%{cipher: :aes_256_gcm_v1}))
      from_binary = V1.encode(sample(%{cipher: "aes_256_gcm_v1", nonce: <<0::96>>}))

      assert {:ok, %{cipher: "aes_256_gcm_v1"}} = Envelope.decode(from_atom)
      assert {:ok, %{cipher: "aes_256_gcm_v1"}} = Envelope.decode(from_binary)
    end

    test "empty ciphertext" do
      blob = V1.encode(sample(%{ciphertext: ""}))
      assert {:ok, %{ciphertext: ""}} = Envelope.decode(blob)
    end

    test "1MB ciphertext" do
      ciphertext = :crypto.strong_rand_bytes(1_048_576)
      blob = V1.encode(sample(%{ciphertext: ciphertext}))
      assert {:ok, %{ciphertext: ^ciphertext}} = Envelope.decode(blob)
    end

    test "key_version 0 and 2^32 - 1 roundtrip" do
      for version <- [0, 1, 4_294_967_295] do
        blob = V1.encode(sample(%{key_version: version}))
        assert {:ok, %{key_version: ^version}} = Envelope.decode(blob)
      end
    end

    test "version/1 reports 1" do
      assert V1.version() == 1
    end
  end

  describe "decode/1 rejections" do
    test "empty input" do
      assert {:error, %InvalidCiphertext{reason: :empty}} = Envelope.decode("")
    end

    test "bare magic with no version byte" do
      assert {:error, %InvalidCiphertext{}} = Envelope.decode("AV")
      assert {:error, %InvalidCiphertext{}} = Envelope.decode("A")
    end

    test "non-AV magic is InvalidCiphertext" do
      for blob <- ["hello world", <<0, 0, 0, 0>>, "BV" <> <<1>>, "av" <> <<1>>] do
        assert {:error, %InvalidCiphertext{}} = Envelope.decode(blob)
      end
    end

    test "good magic with an unknown version byte is UnsupportedEnvelope" do
      for version <- [0, 2, 7, 255] do
        assert {:error, %UnsupportedEnvelope{version: ^version}} =
                 Envelope.decode(<<"AV", version::8, "whatever">>)
      end
    end

    test "truncated at every prefix length, never raising" do
      blob = V1.encode(sample())

      for len <- 0..(byte_size(blob) - 1) do
        prefix = binary_part(blob, 0, len)

        case Envelope.decode(prefix) do
          {:error, %InvalidCiphertext{}} ->
            :ok

          {:ok, decoded} ->
            # Only possible where the truncation lands inside the ciphertext region,
            # which is the binary remainder and therefore not structurally detectable.
            assert byte_size(decoded.ciphertext) < byte_size(sample().ciphertext) or
                     decoded.ciphertext == ""
        end
      end
    end

    test "fuzzing with random binaries never raises" do
      for _ <- 1..2000 do
        blob = :crypto.strong_rand_bytes(:rand.uniform(64) - 1)

        assert match?({:ok, _}, Envelope.decode(blob)) or
                 match?({:error, %{}}, Envelope.decode(blob))
      end
    end

    test "fuzzing with AV-prefixed random binaries never raises" do
      for _ <- 1..2000 do
        blob = "AV" <> :crypto.strong_rand_bytes(:rand.uniform(64) - 1)

        assert match?({:ok, _}, Envelope.decode(blob)) or
                 match?({:error, %{}}, Envelope.decode(blob))
      end
    end

    test "fuzzing by mutating a valid envelope never raises" do
      blob = V1.encode(sample())

      for _ <- 1..2000 do
        index = :rand.uniform(byte_size(blob)) - 1
        <<prefix::binary-size(^index), byte, rest::binary>> = blob
        mutated = <<prefix::binary, Bitwise.bxor(byte, :rand.uniform(255)), rest::binary>>

        assert match?({:ok, _}, Envelope.decode(mutated)) or
                 match?({:error, %{}}, Envelope.decode(mutated))
      end
    end

    test "non-binary and non-byte-aligned input is rejected without raising" do
      assert {:error, %InvalidCiphertext{}} = Envelope.decode(<<1::4>>)
      assert {:error, %InvalidCiphertext{}} = Envelope.decode(:not_a_binary)
      assert {:error, %InvalidCiphertext{}} = V1.decode(:not_a_binary)
    end

    test "V1.decode/1 rejects a foreign version directly" do
      assert {:error, %InvalidCiphertext{}} = V1.decode(<<"AV", 2::8, "rest">>)
    end
  end

  describe "module_for_version/1" do
    test "knows version 1 only" do
      assert {:ok, V1} = Envelope.module_for_version(1)
      assert :error = Envelope.module_for_version(2)
    end

    test "exposes the magic" do
      assert Envelope.magic() == "AV"
    end
  end
end
