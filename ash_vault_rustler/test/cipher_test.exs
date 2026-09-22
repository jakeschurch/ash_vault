defmodule AshVaultRustler.CipherTest do
  use ExUnit.Case, async: false

  alias AshVault.Ciphers.AES.GCM, as: Elixir_GCM
  alias AshVaultRustler.Cipher, as: Rust
  alias AshVaultRustler.Native

  @key :crypto.strong_rand_bytes(32)
  @aad "ashvault:v1|acme|MyApp.Accounts.User|ssn"

  doctest AshVaultRustler

  describe "wire compatibility" do
    test "bytes encrypted by the Elixir cipher decrypt with the Rust one" do
      assert {:ok, payload} = Elixir_GCM.encrypt("attack at dawn", @key, @aad)
      assert {:ok, "attack at dawn"} = Rust.decrypt(payload, @key, @aad)
    end

    test "bytes encrypted by the Rust cipher decrypt with the Elixir one" do
      assert {:ok, payload} = Rust.encrypt("attack at dawn", @key, @aad)
      assert {:ok, "attack at dawn"} = Elixir_GCM.decrypt(payload, @key, @aad)
    end

    test "both directions hold across a range of sizes, including the dirty threshold" do
      for size <- [0, 1, 15, 16, 17, 1_024, 65_535, 65_536, 65_537, 200_000] do
        plaintext = :crypto.strong_rand_bytes(size)

        assert {:ok, from_elixir} = Elixir_GCM.encrypt(plaintext, @key, @aad)
        assert {:ok, ^plaintext} = Rust.decrypt(from_elixir, @key, @aad)

        assert {:ok, from_rust} = Rust.encrypt(plaintext, @key, @aad)
        assert {:ok, ^plaintext} = Elixir_GCM.decrypt(from_rust, @key, @aad)
      end
    end

    test "the two report the same id, key size, nonce size and tag size" do
      assert Rust.id() == Elixir_GCM.id()
      assert Rust.key_bytes() == Elixir_GCM.key_bytes()
      assert Rust.nonce_bytes() == Elixir_GCM.nonce_bytes()
      assert Rust.tag_bytes() == Elixir_GCM.tag_bytes()
    end

    test "the Rust cipher produces the envelope shape the Elixir one does" do
      assert {:ok, %{ciphertext: ct, nonce: nonce, tag: tag}} = Rust.encrypt("hello", @key, @aad)
      assert byte_size(nonce) == 12
      assert byte_size(tag) == 16
      assert byte_size(ct) == byte_size("hello")
    end

    test "a full envelope round trips through AshVault.Envelope.V1 in both directions" do
      assert {:ok, payload} = Rust.encrypt("ssn-here", @key, @aad)

      blob =
        AshVault.Envelope.V1.encode(%{
          version: AshVault.Envelope.V1.version(),
          cipher: Rust.id(),
          key_version: 1,
          nonce: payload.nonce,
          tag: payload.tag,
          ciphertext: payload.ciphertext
        })

      assert {:ok, env} = AshVault.Envelope.decode(blob)
      assert env.cipher == "aes_256_gcm_v1"

      # Whichever implementation the registry resolves for that id, both can read the
      # bytes — which is exactly the interchangeability being asserted.
      assert {:ok, resolved} = AshVault.Cipher.fetch(env.cipher)
      assert resolved in [AshVault.Ciphers.AES.GCM, AshVaultRustler.Cipher]

      assert {:ok, "ssn-here"} =
               AshVault.Ciphers.AES.GCM.decrypt(
                 %{ciphertext: env.ciphertext, nonce: env.nonce, tag: env.tag},
                 @key,
                 @aad
               )
    end
  end

  describe "rejections match the Elixir cipher" do
    setup do
      {:ok, payload} = Rust.encrypt("secret", @key, @aad)
      %{payload: payload}
    end

    test "a truncated tag is refused at every length", %{payload: payload} do
      for len <- [0, 1, 2, 4, 8, 12, 15, 17, 32] do
        forged = %{payload | tag: binary_part(payload.tag <> <<0::256>>, 0, len)}

        assert {:error, :auth_failed} = Rust.decrypt(forged, @key, @aad),
               "a #{len}-byte tag was not refused"

        assert {:error, :auth_failed} = Elixir_GCM.decrypt(forged, @key, @aad)
      end
    end

    test "a nonce that is not 12 bytes is refused", %{payload: payload} do
      for len <- [0, 1, 8, 11, 13, 16] do
        forged = %{payload | nonce: binary_part(payload.nonce <> <<0::256>>, 0, len)}

        assert {:error, :auth_failed} = Rust.decrypt(forged, @key, @aad)
        assert {:error, :auth_failed} = Elixir_GCM.decrypt(forged, @key, @aad)
      end
    end

    test "a wrong AAD fails, so the scope/resource/field binding holds", %{payload: payload} do
      assert {:error, :auth_failed} = Rust.decrypt(payload, @key, "ashvault:v1|other|X|y")
    end

    test "a flipped ciphertext bit fails", %{payload: payload} do
      <<first, rest::binary>> = payload.ciphertext
      forged = %{payload | ciphertext: <<Bitwise.bxor(first, 1), rest::binary>>}
      assert {:error, :auth_failed} = Rust.decrypt(forged, @key, @aad)
    end

    test "a wrong key size is a distinct, non-tampering error", %{payload: payload} do
      assert {:error, {:invalid_key_size, 16}} = Rust.encrypt("x", <<0::128>>, @aad)
      assert {:error, {:invalid_key_size, 16}} = Rust.decrypt(payload, <<0::128>>, @aad)
    end

    test "a malformed payload is refused" do
      assert {:error, :auth_failed} = Rust.decrypt(%{}, @key, @aad)
      assert {:error, :auth_failed} = Rust.decrypt("not a payload", @key, @aad)
    end
  end

  describe "opaque keys" do
    test "encrypt and decrypt work against a handle" do
      key = %AshVault.Key{ref: Native.key_handle_new(@key), owner: __MODULE__}

      assert {:ok, payload} = Rust.encrypt("through a handle", key, @aad)
      assert {:ok, "through a handle"} = Rust.decrypt(payload, key, @aad)
    end

    test "a handle is wire-compatible with the binary key it was made from" do
      key = %AshVault.Key{ref: Native.key_handle_new(@key), owner: __MODULE__}

      assert {:ok, payload} = Rust.encrypt("both ways", key, @aad)
      assert {:ok, "both ways"} = Elixir_GCM.decrypt(payload, @key, @aad)

      assert {:ok, other} = Elixir_GCM.encrypt("both ways", @key, @aad)
      assert {:ok, "both ways"} = Rust.decrypt(other, key, @aad)
    end

    test "the built-in Elixir cipher refuses a handle rather than falling back" do
      key = %AshVault.Key{ref: Native.key_handle_new(@key), owner: __MODULE__}

      assert {:error, :opaque_key_unsupported} = Elixir_GCM.encrypt("x", key, @aad)

      assert {:error, :opaque_key_unsupported} =
               Elixir_GCM.decrypt(
                 %{ciphertext: "x", nonce: <<0::96>>, tag: <<0::128>>},
                 key,
                 @aad
               )
    end

    test "a foreign reference is refused, not treated as a key" do
      key = %AshVault.Key{ref: make_ref(), owner: __MODULE__}
      assert {:error, :opaque_key_unsupported} = Rust.encrypt("x", key, @aad)
    end

    test "a handle carries no key bytes in its inspect output" do
      key = %AshVault.Key{ref: Native.key_handle_new(@key), owner: __MODULE__}
      inspected = inspect(key)

      refute inspected =~ Base.encode16(@key)
      assert inspected =~ "owner"
    end

    test "key_handle_new refuses anything that is not 32 bytes" do
      assert {:error, :invalid_key_size} = Native.key_handle_new(<<0::128>>)
      assert {:error, :invalid_key_size} = Native.key_handle_new(<<>>)
      assert is_reference(Native.key_handle_new(<<0::256>>))
    end
  end

  describe "scheduler dispatch" do
    test "the threshold is configurable and both paths produce the same answer" do
      plaintext = :crypto.strong_rand_bytes(4_096)

      assert {:ok, normal} = Native.encrypt(@key, plaintext, @aad)
      assert {:ok, dirty} = Native.encrypt_dirty(@key, plaintext, @aad)

      {ct_n, nonce_n, tag_n} = normal
      {ct_d, nonce_d, tag_d} = dirty

      # Different nonces, therefore different ciphertexts — but both decrypt.
      refute nonce_n == nonce_d

      assert {:ok, ^plaintext} = Native.decrypt(@key, ct_n, nonce_n, tag_n, @aad)
      assert {:ok, ^plaintext} = Native.decrypt_dirty(@key, ct_d, nonce_d, tag_d, @aad)
    end

    test "dirty_threshold_bytes is 64 KiB by default" do
      assert Rust.dirty_threshold_bytes() == 65_536
    end
  end
end
