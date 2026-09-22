# Writing a cipher

A cipher turns `(plaintext, key, aad)` into `(ciphertext, nonce, tag)` and back. AshVault
ships one, `AshVault.Ciphers.AES.GCM`, and you should have a specific reason before adding
another — a hardware requirement, a compliance rule naming a different algorithm, or a
migration away from one.

## The contract

```elixir
@type payload :: %{ciphertext: binary(), nonce: binary(), tag: binary()}

@callback id() :: atom()
@callback key_bytes() :: pos_integer()
@callback encrypt(plaintext :: binary(), key :: binary(), aad :: binary()) ::
            {:ok, payload()} | {:error, term()}
@callback decrypt(payload(), key :: binary(), aad :: binary()) ::
            {:ok, binary()} | {:error, term()}
```

Rules:

* **`id/0` is forever.** It is written into every envelope and is how a value is matched
  back to the code that can open it. Version it in the name (`:aes_256_gcm_v1`), and if
  you change the algorithm, parameters, or framing in any observable way, mint a *new* id
  rather than redefining the old one. Values already in the database still say the old id.
* **It must be an AEAD.** `aad` is not optional decoration: it is
  `"ashvault:v1|<scope>|<Resource>|<field>"`, and binding it into the tag is what stops a
  ciphertext being relocated between tenants, resources and columns. A cipher that ignores
  `aad` silently removes threats 4, 5 and 6 from [the threat model](../topics/threat-model.md).
* **Fresh nonce per encryption.** Never a counter derived from anything in the row. GCM
  nonce reuse under the same key is catastrophic — it leaks the XOR of two plaintexts and
  the authentication subkey.
* **`key_bytes/0` must be exact.** `AshVault.Vault.verify_key_sizes!/2` compares it with
  the provider's `key_bytes/0` at compile time where it can, and
  `AshVault.Vault.Runtime` raises `AshVault.Errors.KeySizeMismatch` at the point of use
  where it cannot.
* **Error vocabulary.** Return `{:error, {:invalid_key_size, n}}` for a wrong-size key and
  `{:error, :auth_failed}` (or any other term) for a verification failure. The first is
  mapped to `AshVault.Errors.KeySizeMismatch` — a configuration fault, not retryable and
  not tampering; everything else becomes `AshVault.Errors.AuthenticationFailed`. Getting
  this backwards tells an operator their data was tampered with when they made a typo in
  `config/runtime.exs`.

## Failure modes that matter

### Validate nonce and tag lengths yourself, before `:crypto`

This is the single sharpest edge in the whole cipher layer, and it is not obvious.

The envelope stores `nonce_len` and `tag_len` as bytes read straight out of the database.
`:crypto.crypto_one_time_aead/7` on OTP 29 **accepts a truncated GCM tag** — verified: 1,
2, 4, 8 and 12-byte tags all return plaintext, compared only over their leading bytes;
only a 0-byte tag is rejected. GCM is CTR mode, so an attacker with database write access
can XOR the ciphertext to any chosen plaintext, store `tag_len: 1`, and enumerate 256
values. Success is guaranteed within 256 read attempts.

Likewise a short nonce is a perfectly valid input to the primitive: OTP derives J0 by
GHASHing anything that is not 96 bits, so a 1-byte nonce widens the space an attacker
controls rather than erroring.

So check both, before the key touches `:crypto`:

```elixir
defp validate_nonce(nonce) when byte_size(nonce) == @nonce_bytes, do: :ok
defp validate_nonce(_nonce), do: {:error, :auth_failed}

defp validate_tag(tag) when byte_size(tag) == @tag_bytes, do: :ok
defp validate_tag(_tag), do: {:error, :auth_failed}
```

Do not make these configurable. A per-vault `tag_bytes` option is an invitation to
downgrade the forgery bound in config.

### Do not let `:crypto` raise through

`:crypto` raises on some malformed inputs. `decrypt/3` is called with bytes from the
database, so wrap it:

```elixir
defp safe_decrypt(ciphertext, key, nonce, tag, aad) do
  :crypto.crypto_one_time_aead(@cipher, key, nonce, ciphertext, aad, tag, false)
rescue
  _ -> :error
end
```

A `FunctionClauseError` or an `ErlangError` escaping the cipher is an unhelpful 500 where
an `AuthenticationFailed` belonged.

### Add a total fallback clause

```elixir
def decrypt(_payload, _key, _aad), do: {:error, :auth_failed}
```

A payload map that does not have the three expected binary keys is not a decryptable
payload; say so as a value rather than a match error.

## A worked example

ChaCha20-Poly1305: 32-byte keys, 12-byte nonces, 16-byte tags.

```elixir
defmodule MyApp.Ciphers.ChaCha20Poly1305 do
  @moduledoc """
  ChaCha20-Poly1305 for AshVault.

  32-byte keys, fresh 12-byte nonces per encryption, 16-byte tags. The AshVault
  associated data is bound into the tag, so a value only decrypts under the same
  scope, resource and field.
  """

  @behaviour AshVault.Cipher

  @cipher :chacha20_poly1305
  @key_bytes 32
  @nonce_bytes 12
  @tag_bytes 16

  @impl AshVault.Cipher
  def id, do: :chacha20_poly1305_v1

  @impl AshVault.Cipher
  def key_bytes, do: @key_bytes

  @impl AshVault.Cipher
  def encrypt(plaintext, key, aad)
      when is_binary(plaintext) and is_binary(key) and is_binary(aad) do
    with :ok <- validate_key(key) do
      nonce = :crypto.strong_rand_bytes(@nonce_bytes)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(@cipher, key, nonce, plaintext, aad, true)

      {:ok, %{ciphertext: ciphertext, nonce: nonce, tag: tag}}
    end
  end

  @impl AshVault.Cipher
  def decrypt(%{ciphertext: ciphertext, nonce: nonce, tag: tag}, key, aad)
      when is_binary(ciphertext) and is_binary(nonce) and is_binary(tag) and
             is_binary(key) and is_binary(aad) do
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

  defp validate_nonce(nonce) when byte_size(nonce) == @nonce_bytes, do: :ok
  defp validate_nonce(_nonce), do: {:error, :auth_failed}

  defp validate_tag(tag) when byte_size(tag) == @tag_bytes, do: :ok
  defp validate_tag(_tag), do: {:error, :auth_failed}
end
```

## Registering it

Two steps. First, put it in the registry so **decryption** can find it by id — the
registry is keyed by the binary id, exactly what the envelope stores:

```elixir
# config/config.exs
config :ash_vault, :ciphers, %{
  "chacha20_poly1305_v1" => MyApp.Ciphers.ChaCha20Poly1305
}
```

Then point a vault at it so **new writes** use it:

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault,
    key_provider: MyApp.KeyProviders.Sql,
    cipher: MyApp.Ciphers.ChaCha20Poly1305
end
```

Registry and vault are separate on purpose. Leaving the *old* cipher in the registry is
how existing rows keep decrypting after you switch the default — `AshVault.Vault.Runtime`
resolves the cipher from the envelope, never from the vault's configuration. Remove a
cipher from the registry only once nothing in the database names it; until then a row
carrying it fails with:

```
Unsupported cipher: "chacha20_poly1305_v1".

Register it under `config :ash_vault, :ciphers, %{...}` if this build should support it.
```

There is no migration tool for re-encrypting old rows onto a new cipher. The mechanism is
the same as for [rotation](../topics/rotation.md): read and re-save the rows, which
re-encrypts them with the vault's current cipher and current key.

## Testing it

`test/ash_vault/ciphers/aes_gcm_test.exs` and `test/ash_vault/cipher_test.exs` are the
model. At minimum assert:

* roundtrip, including empty plaintext and a large (1MB) plaintext;
* a flipped ciphertext byte fails; a flipped tag byte fails; a flipped nonce byte fails;
* the wrong key fails;
* a **different AAD** fails — this is the one that proves relocation is impossible;
* 1000 encryptions produce 1000 distinct nonces;
* a key of the wrong size returns `{:error, {:invalid_key_size, n}}`, not `:auth_failed`;
* a truncated tag (1, 2, 4, 8, 12 bytes) is **rejected**, and so is a short nonce;
* `AshVault.Cipher.fetch("your_id")` returns your module once registered.

## Related

* `AshVault.Cipher`, `AshVault.Ciphers.AES.GCM`
* [Architecture](../topics/architecture.md) — where the AAD comes from
* [Threat model](../topics/threat-model.md)
