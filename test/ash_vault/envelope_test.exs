defmodule AshVault.EnvelopeTest do
  use ExUnit.Case, async: true

  import Bitwise

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

    # P2 #17. `match?({:error, %{}}, ...)` passes on ANY struct, so the fuzz tests
    # proved only "did not raise" — a misclassification (InvalidCiphertext where
    # UnsupportedEnvelope is owed, or vice versa) sailed straight through. Every
    # outcome below is now pinned to the struct the magic and version byte demand.
    defp assert_classified(blob) do
      result = Envelope.decode(blob)

      case blob do
        <<"AV", 1::8, _rest::binary>> ->
          assert match?({:ok, %{version: 1}}, result) or
                   match?({:error, %InvalidCiphertext{}}, result),
                 "a v1 envelope must decode or be InvalidCiphertext, got #{inspect(result)}"

        <<"AV", version::8, _rest::binary>> ->
          assert {:error, %UnsupportedEnvelope{version: ^version}} = result

        _other ->
          assert {:error, %InvalidCiphertext{}} = result
      end

      result
    end

    test "fuzzing with random binaries is always classified correctly" do
      for _ <- 1..2000 do
        assert_classified(:crypto.strong_rand_bytes(:rand.uniform(64) - 1))
      end
    end

    test "fuzzing with AV-prefixed random binaries is always classified correctly" do
      for _ <- 1..2000 do
        assert_classified("AV" <> :crypto.strong_rand_bytes(:rand.uniform(64) - 1))
      end
    end

    test "fuzzing by mutating a valid envelope is always classified correctly" do
      blob = V1.encode(sample())

      for _ <- 1..2000 do
        index = :rand.uniform(byte_size(blob)) - 1
        <<prefix::binary-size(^index), byte, rest::binary>> = blob
        mutated = <<prefix::binary, Bitwise.bxor(byte, :rand.uniform(255)), rest::binary>>

        assert_classified(mutated)
      end
    end

    test "a mutated version byte is UnsupportedEnvelope, never InvalidCiphertext" do
      blob = V1.encode(sample())
      <<"AV", _version::8, rest::binary>> = blob

      for version <- 0..255, version != 1 do
        assert {:error, %UnsupportedEnvelope{version: ^version}} =
                 Envelope.decode(<<"AV", version::8, rest::binary>>)
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

  describe "encode/1 rejects unencodable envelopes symmetrically (P2 #20)" do
    # An over-long cipher id got a clean ArgumentError while an over-long nonce or tag,
    # or a key_version past 2^32-1, fell off the guard clause as an opaque
    # FunctionClauseError — the same class of mistake reported two different ways.
    test "an over-long cipher id, nonce or tag all raise ArgumentError naming the field" do
      long = :crypto.strong_rand_bytes(256)

      assert_raise ArgumentError, ~r/cipher_id is too long.*at most 255 bytes/s, fn ->
        V1.encode(sample(%{cipher: Base.encode16(long)}))
      end

      assert_raise ArgumentError, ~r/nonce is too long.*at most 255 bytes/s, fn ->
        V1.encode(sample(%{nonce: long}))
      end

      assert_raise ArgumentError, ~r/tag is too long.*at most 255 bytes/s, fn ->
        V1.encode(sample(%{tag: long}))
      end
    end

    test "exactly 255 bytes still encodes, and roundtrips" do
      nonce = :crypto.strong_rand_bytes(255)
      tag = :crypto.strong_rand_bytes(255)

      blob = V1.encode(sample(%{nonce: nonce, tag: tag}))
      assert {:ok, %{nonce: ^nonce, tag: ^tag}} = Envelope.decode(blob)
    end

    test "a key_version past 2^32-1 raises ArgumentError, not FunctionClauseError" do
      for version <- [4_294_967_296, 4_294_967_300, 1 <<< 64, -1] do
        error =
          assert_raise ArgumentError, fn -> V1.encode(sample(%{key_version: version})) end

        assert Exception.message(error) =~ "key_version is out of range"
        assert Exception.message(error) =~ "0 and 4294967295"
      end
    end

    test "non-binary and non-integer fields raise ArgumentError too" do
      assert_raise ArgumentError, ~r/key_version must be an integer/, fn ->
        V1.encode(sample(%{key_version: "1"}))
      end

      assert_raise ArgumentError, ~r/nonce must be a binary/, fn ->
        V1.encode(sample(%{nonce: nil}))
      end

      assert_raise ArgumentError, ~r/tag must be a binary/, fn ->
        V1.encode(sample(%{tag: 16}))
      end

      assert_raise ArgumentError, ~r/ciphertext must be a binary/, fn ->
        V1.encode(sample(%{ciphertext: nil}))
      end

      assert_raise ArgumentError, ~r/cipher must be an atom or a binary/, fn ->
        V1.encode(sample(%{cipher: 42}))
      end

      assert_raise ArgumentError, ~r/not an encodable AshVault envelope/, fn ->
        V1.encode(%{cipher: :aes_256_gcm_v1})
      end
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
