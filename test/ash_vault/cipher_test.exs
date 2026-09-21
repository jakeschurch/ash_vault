defmodule AshVault.CipherTest do
  use ExUnit.Case, async: true

  alias AshVault.Cipher
  alias AshVault.Errors.UnsupportedCipher

  describe "fetch/1" do
    test "resolves the built-in cipher by atom and by binary" do
      assert {:ok, AshVault.Ciphers.AES.GCM} = Cipher.fetch(:aes_256_gcm_v1)
      assert {:ok, AshVault.Ciphers.AES.GCM} = Cipher.fetch("aes_256_gcm_v1")
    end

    test "the registry is keyed by the binary id the envelope stores" do
      assert Map.has_key?(Cipher.registry(), "aes_256_gcm_v1")
    end

    test "an unknown binary id is an UnsupportedCipher error, not an atom leak" do
      id = "definitely_not_a_cipher_#{System.unique_integer([:positive])}"

      assert {:error, %UnsupportedCipher{cipher_id: ^id}} = Cipher.fetch(id)

      assert_raise ArgumentError, fn -> String.to_existing_atom(id) end
    end

    test "non-id terms are rejected without raising" do
      for term <- [nil, 42, <<0, 1, 2>>, "", {:tuple}] do
        assert {:error, %UnsupportedCipher{}} = Cipher.fetch(term)
      end
    end
  end
end
