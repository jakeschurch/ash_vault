defmodule AshVault.Ciphers.AES.GCMTest do
  use ExUnit.Case, async: true

  alias AshVault.Ciphers.AES.GCM

  @aad "ashvault:v1|acme|MyApp.User|ssn"

  defp key, do: :crypto.strong_rand_bytes(32)

  describe "metadata" do
    test "id and key size are the frozen values" do
      assert GCM.id() == :aes_256_gcm_v1
      assert GCM.key_bytes() == 32
    end
  end

  describe "roundtrip" do
    test "encrypt then decrypt returns the plaintext" do
      key = key()
      assert {:ok, payload} = GCM.encrypt("hunter2", key, @aad)
      assert byte_size(payload.nonce) == 12
      assert byte_size(payload.tag) == 16
      assert {:ok, "hunter2"} = GCM.decrypt(payload, key, @aad)
    end

    test "empty plaintext roundtrips" do
      key = key()
      assert {:ok, payload} = GCM.encrypt("", key, @aad)
      assert payload.ciphertext == ""
      assert {:ok, ""} = GCM.decrypt(payload, key, @aad)
    end

    test "large plaintext roundtrips" do
      key = key()
      plaintext = :crypto.strong_rand_bytes(1_000_000)
      assert {:ok, payload} = GCM.encrypt(plaintext, key, @aad)
      assert {:ok, ^plaintext} = GCM.decrypt(payload, key, @aad)
    end

    test "empty aad roundtrips" do
      key = key()
      assert {:ok, payload} = GCM.encrypt("x", key, "")
      assert {:ok, "x"} = GCM.decrypt(payload, key, "")
    end
  end

  describe "authentication" do
    test "aad mismatch fails" do
      key = key()
      assert {:ok, payload} = GCM.encrypt("hunter2", key, @aad)
      assert {:error, :auth_failed} = GCM.decrypt(payload, key, @aad <> "!")
    end

    test "flipped ciphertext byte fails" do
      key = key()
      assert {:ok, payload} = GCM.encrypt("hunter2", key, @aad)
      tampered = %{payload | ciphertext: flip_byte(payload.ciphertext, 0)}
      assert {:error, :auth_failed} = GCM.decrypt(tampered, key, @aad)
    end

    test "flipped tag byte fails" do
      key = key()
      assert {:ok, payload} = GCM.encrypt("hunter2", key, @aad)
      tampered = %{payload | tag: flip_byte(payload.tag, 3)}
      assert {:error, :auth_failed} = GCM.decrypt(tampered, key, @aad)
    end

    test "flipped nonce byte fails" do
      key = key()
      assert {:ok, payload} = GCM.encrypt("hunter2", key, @aad)
      tampered = %{payload | nonce: flip_byte(payload.nonce, 5)}
      assert {:error, :auth_failed} = GCM.decrypt(tampered, key, @aad)
    end

    test "wrong key fails" do
      assert {:ok, payload} = GCM.encrypt("hunter2", key(), @aad)
      assert {:error, :auth_failed} = GCM.decrypt(payload, key(), @aad)
    end

    test "a malformed payload fails instead of raising" do
      assert {:error, :auth_failed} =
               GCM.decrypt(%{ciphertext: "", nonce: "", tag: ""}, key(), "")

      assert {:error, :auth_failed} = GCM.decrypt(%{}, key(), "")
    end
  end

  describe "nonces" do
    test "1000 encryptions produce 1000 distinct nonces" do
      key = key()

      nonces =
        for _ <- 1..1000 do
          {:ok, payload} = GCM.encrypt("same plaintext", key, @aad)
          payload.nonce
        end

      assert length(Enum.uniq(nonces)) == 1000
    end
  end

  describe "key validation" do
    test "rejects a key that is not 32 bytes" do
      for size <- [0, 1, 16, 24, 31, 33, 64] do
        key = :crypto.strong_rand_bytes(size)
        assert {:error, {:invalid_key_size, ^size}} = GCM.encrypt("x", key, @aad)
      end
    end

    test "decrypt rejects a bad key size" do
      {:ok, payload} = GCM.encrypt("x", key(), @aad)
      assert {:error, {:invalid_key_size, 16}} = GCM.decrypt(payload, <<0::128>>, @aad)
    end
  end

  defp flip_byte(binary, index) do
    <<prefix::binary-size(^index), byte, rest::binary>> = binary
    <<prefix::binary, Bitwise.bxor(byte, 0xFF), rest::binary>>
  end
end
