defmodule AshVault.Ciphers.AES.GCM do
  @moduledoc """
  AES-256-GCM, the default AshVault cipher.

  * 32-byte keys (256 bit)
  * 12-byte nonces, freshly generated from `:crypto.strong_rand_bytes/1` per encryption
  * 16-byte authentication tags
  * the associated data built by `AshVault.Vault.Runtime.build_aad/2` is bound into the
    tag, so a ciphertext only decrypts under the same scope, resource and field

  Nonce and tag sizes are deliberately not configurable, and `decrypt/3` **rejects any
  payload whose nonce is not 12 bytes or whose tag is not 16 bytes** before the key
  touches `:crypto`.

  > #### Why the length check is a security control, not a tidiness check {: .error}
  >
  > `:crypto.crypto_one_time_aead/7` on OTP 29 accepts a truncated GCM tag (verified:
  > 1, 2, 4, 8 and 12 bytes all return plaintext; only a 0-byte tag is rejected) and
  > compares only the leading N bytes. The AshVault envelope carries `tag_len` as a
  > byte read straight out of the database, so an attacker with database write access
  > could store a forged row with `tag_len: 1` and enumerate 256 values — GCM is CTR
  > mode, so the ciphertext can be XORed to any chosen plaintext first. Success was
  > guaranteed within 256 read attempts. Requiring the full 16-byte tag restores the
  > 2^-128 forgery bound.
  """

  @behaviour AshVault.Cipher

  @cipher :aes_256_gcm
  @key_bytes 32
  @nonce_bytes 12
  @tag_bytes 16

  @doc """
  The stable cipher id, `:aes_256_gcm_v1`.
  """
  @impl AshVault.Cipher
  @spec id() :: :aes_256_gcm_v1
  def id, do: :aes_256_gcm_v1

  @doc """
  The required key size in bytes, `32`.
  """
  @impl AshVault.Cipher
  @spec key_bytes() :: pos_integer()
  def key_bytes, do: @key_bytes

  @doc """
  Encrypt `plaintext` with a fresh random nonce.

  Returns `{:error, {:invalid_key_size, n}}` if the key is not exactly 32 bytes.
  """
  @impl AshVault.Cipher
  @spec encrypt(binary(), binary(), binary()) ::
          {:ok, AshVault.Cipher.payload()} | {:error, term()}
  def encrypt(plaintext, key, aad)
      when is_binary(plaintext) and is_binary(key) and is_binary(aad) do
    with :ok <- validate_key(key) do
      nonce = :crypto.strong_rand_bytes(@nonce_bytes)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(@cipher, key, nonce, plaintext, aad, true)

      {:ok, %{ciphertext: ciphertext, nonce: nonce, tag: tag}}
    end
  end

  @doc """
  Decrypt a payload, verifying the tag against `aad`.

  Returns `{:error, :auth_failed}` when the tag does not verify, when the tag is not
  exactly 16 bytes, or when the nonce is not exactly 12 bytes; and
  `{:error, {:invalid_key_size, n}}` for a key that is not exactly 32 bytes.

  The tag and nonce lengths are checked *before* `:crypto` sees them: OTP accepts a
  truncated tag and compares only its leading bytes, which turns an attacker-controlled
  `tag_len` in the envelope into a ≤256-guess forgery. See the moduledoc.
  """
  @impl AshVault.Cipher
  @spec decrypt(AshVault.Cipher.payload(), binary(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt(%{ciphertext: ciphertext, nonce: nonce, tag: tag}, key, aad)
      when is_binary(ciphertext) and is_binary(nonce) and is_binary(tag) and is_binary(key) and
             is_binary(aad) do
    with :ok <- validate_key(key),
         :ok <- validate_nonce(nonce),
         :ok <- validate_tag(tag) do
      case safe_decrypt(ciphertext, key, nonce, tag, aad) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        _other -> {:error, :auth_failed}
      end
    end
  end

  def decrypt(_payload, _key, _aad), do: {:error, :auth_failed}

  defp safe_decrypt(ciphertext, key, nonce, tag, aad) do
    :crypto.crypto_one_time_aead(@cipher, key, nonce, ciphertext, aad, tag, false)
  rescue
    _ -> :error
  end

  defp validate_key(key) when byte_size(key) == @key_bytes, do: :ok
  defp validate_key(key), do: {:error, {:invalid_key_size, byte_size(key)}}

  # A short nonce is not a GCM nonce: OTP derives J0 by GHASHing anything that is not
  # 96 bits, so a 1-byte nonce is a perfectly valid input to the primitive and would
  # silently widen the space an attacker controls. Only 12 bytes is ours.
  defp validate_nonce(nonce) when byte_size(nonce) == @nonce_bytes, do: :ok
  defp validate_nonce(_nonce), do: {:error, :auth_failed}

  # A truncated tag is accepted by `:crypto` and compared only over its leading bytes.
  # Refusing anything but the full 16 bytes is what keeps the forgery bound at 2^-128.
  defp validate_tag(tag) when byte_size(tag) == @tag_bytes, do: :ok
  defp validate_tag(_tag), do: {:error, :auth_failed}

  @doc false
  @spec tag_bytes() :: pos_integer()
  def tag_bytes, do: @tag_bytes

  @doc false
  @spec nonce_bytes() :: pos_integer()
  def nonce_bytes, do: @nonce_bytes
end
