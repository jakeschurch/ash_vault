defmodule AshVault.Errors do
  @moduledoc """
  Error structs raised and returned by the AshVault crypto core.

  Every error is a [Splode](https://hex.pm/packages/splode) error struct, which means it
  is a regular `Exception` that can be raised, but also carries a `:class` (always
  `:invalid` here) so it can be aggregated by Ash's error handling.

  The modules are:

    * `AshVault.Errors.MissingScope` — the encryption scope could not be resolved
    * `AshVault.Errors.KeyNotFound` — the provider has no such key and no tombstone
    * `AshVault.Errors.KeyDestroyed` — the key was deliberately destroyed (crypto-erasure)
    * `AshVault.Errors.ProviderUnavailable` — transport/backend failure, retryable
    * `AshVault.Errors.AuthenticationFailed` — AEAD tag mismatch
    * `AshVault.Errors.UnsupportedEnvelope` — envelope version this build cannot parse
    * `AshVault.Errors.UnsupportedCipher` — cipher id not in the registry
    * `AshVault.Errors.InvalidCiphertext` — malformed, truncated or foreign bytes

  A destroyed key must never surface as `AshVault.Errors.AuthenticationFailed`:
  destruction is checked before any decryption is attempted.
  """
end

defmodule AshVault.Errors.MissingScope do
  @moduledoc """
  Raised when the encryption scope for a field could not be resolved.

  The most common cause is executing an Ash action without a tenant against a resource
  that uses tenant-scoped encryption.
  """

  use Splode.Error, fields: [:resource, :field, :scope_module, :reason], class: :invalid

  def message(%{resource: resource, field: field}) do
    """
    Cannot encrypt #{inspect(resource)}.#{field} because no Ash tenant was present.

    This resource uses tenant-scoped encryption.
    Pass a tenant when executing the Ash action or configure another AshVault scope.
    """
  end
end

defmodule AshVault.Errors.KeyNotFound do
  @moduledoc """
  Raised when the key provider has no key for the requested scope and version,
  and no tombstone recording that it was destroyed.
  """

  use Splode.Error, fields: [:scope, :key_version], class: :invalid

  def message(%{scope: scope, key_version: version}) do
    """
    No encryption key found for scope #{inspect(scope)} (version #{inspect(version)}).
    """
  end
end

defmodule AshVault.Errors.KeyDestroyed do
  @moduledoc """
  Raised when the key needed to decrypt a value was deliberately destroyed.

  This is crypto-erasure: the data is unrecoverable by design.
  """

  use Splode.Error, fields: [:scope, :key_version, :resource, :field], class: :invalid

  def message(%{scope: scope, key_version: v}) do
    """
    Encryption key for scope #{inspect(scope)} (version #{inspect(v)}) has been destroyed.

    This data was cryptographically erased and cannot be recovered.
    """
  end
end

defmodule AshVault.Errors.ProviderUnavailable do
  @moduledoc """
  Raised when the key provider could not be reached or failed for a transient reason.

  Unlike the other errors in this namespace, this one is generally retryable.
  """

  use Splode.Error, fields: [:provider, :reason], class: :invalid

  def message(%{provider: provider, reason: reason}) do
    """
    Key provider #{inspect(provider)} is unavailable: #{inspect(reason)}.
    """
  end
end

defmodule AshVault.Errors.AuthenticationFailed do
  @moduledoc """
  Raised when the AEAD authentication tag does not verify.

  Causes include tampering with the stored ciphertext, decrypting with the wrong key,
  or decrypting under different associated data (a different scope, resource or field).
  """

  use Splode.Error, fields: [:resource, :field, :key_version], class: :invalid

  def message(%{resource: resource, field: field, key_version: version}) do
    """
    Failed to authenticate ciphertext for #{inspect(resource)}.#{field} (key version #{inspect(version)}).

    The data was tampered with, decrypted with the wrong key, or decrypted under
    different associated data.
    """
  end
end

defmodule AshVault.Errors.UnsupportedEnvelope do
  @moduledoc """
  Raised when an envelope carries a version byte this build does not know how to parse.
  """

  use Splode.Error, fields: [:version], class: :invalid

  def message(%{version: version}) do
    """
    Unsupported AshVault envelope version: #{inspect(version)}.
    """
  end
end

defmodule AshVault.Errors.UnsupportedCipher do
  @moduledoc """
  Raised when an envelope names a cipher that is not present in the cipher registry.
  """

  use Splode.Error, fields: [:cipher_id], class: :invalid

  def message(%{cipher_id: cipher_id}) do
    """
    Unsupported cipher: #{inspect(cipher_id)}.

    Register it under `config :ash_vault, :ciphers, %{...}` if this build should support it.
    """
  end
end

defmodule AshVault.Errors.InvalidCiphertext do
  @moduledoc """
  Raised when a stored value is not a well-formed AshVault envelope.
  """

  use Splode.Error, fields: [:reason], class: :invalid

  def message(%{reason: reason}) do
    """
    Value is not a valid AshVault envelope: #{inspect(reason)}.
    """
  end
end
