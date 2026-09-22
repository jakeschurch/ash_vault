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
    * `AshVault.Errors.KeySizeMismatch` — the provider's keys are the wrong size for
      the cipher; a configuration fault, **not** retryable and not tampering
    * `AshVault.Errors.InvalidScope` — an `AshVault.Scope` returned a non-binary key
    * `AshVault.Errors.OpaqueKeyUnsupported` — the provider returned an opaque
      `AshVault.Key` handle and the cipher can only use raw bytes; a configuration
      fault, not retryable and not tampering

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

  use Splode.Error,
    fields: [:resource, :field, :scope_module, :reason, :tenant, :operation],
    class: :invalid

  def message(%{reason: :unsupported_tenant_shape} = error) do
    """
    Cannot #{verb(error)} #{inspect(error.resource)}.#{error.field} because the tenant is \
    of a shape #{inspect(error.scope_module)} cannot turn into a stable scope key.

    Received: #{error.tenant || "(not recorded)"}

    A tenant was present — this is not a missing-tenant error. Accepted shapes are:

      * a binary, used as-is
      * an atom or an integer, stringified
      * a struct with a non-nil `:id`, reduced to the stringified id

    To support another shape, implement `to_scope_key/2` in your own
    `AshVault.Scope` module (see `#{inspect(error.scope_module)}.to_scope_key/2`) and
    configure it as the vault's `:scope`.
    """
  end

  def message(%{reason: reason} = error) when reason not in [nil, :no_tenant] do
    """
    Cannot #{verb(error)} #{inspect(error.resource)}.#{error.field}: \
    #{inspect(error.scope_module)} could not resolve a scope (#{inspect(reason)}).
    """
  end

  def message(%{resource: resource, field: field} = error) do
    """
    Cannot #{verb(error)} #{inspect(resource)}.#{field} because no Ash tenant was present.

    This resource uses tenant-scoped encryption.
    Pass a tenant when executing the Ash action or configure another AshVault scope.
    """
  end

  defp verb(%{operation: :decrypt}), do: "decrypt"
  defp verb(_error), do: "encrypt"
end

defmodule AshVault.Errors.KeySizeMismatch do
  @moduledoc """
  Raised when the key material a provider supplies is not the size the cipher requires.

  This is a **configuration** fault — a `key_bytes:` that disagrees with the cipher, an
  OpenBao `key_type:` of `aes128-gcm96` under a 256-bit cipher, a truncated key file.
  It is deliberately neither `AshVault.Errors.AuthenticationFailed` (which would tell
  an operator their data had been tampered with) nor
  `AshVault.Errors.ProviderUnavailable` (which would tell them to retry a permanent
  misconfiguration forever). Fix the configuration; retrying cannot help.
  """

  use Splode.Error, fields: [:provider, :cipher, :expected, :actual], class: :invalid

  def message(%{provider: provider, cipher: cipher, expected: expected, actual: actual}) do
    """
    Key size mismatch: #{inspect(cipher)} requires #{inspect(expected)}-byte keys, but \
    #{inspect(provider)} supplied #{inspect(actual)} bytes.

    This is a configuration fault, not tampering and not an outage. Retrying will not
    help. Check the provider's `:key_bytes` (or OpenBao's `:key_type`) against the
    vault's `:cipher`.
    """
  end
end

defmodule AshVault.Errors.InvalidScope do
  @moduledoc """
  Raised when an `AshVault.Scope` implementation returns something other than a binary.

  Scope keys address key material in the provider and are baked into the AAD of every
  ciphertext, so they must be stable across processes, releases and OTP upgrades. A
  non-binary term is not: `:erlang.term_to_binary/1` is explicitly not stable, and an
  encoding change would relocate a tenant's tombstone and key name at once.
  """

  use Splode.Error, fields: [:scope_module, :scope, :resource, :field], class: :invalid

  def message(%{scope_module: scope_module, scope: scope}) do
    """
    #{inspect(scope_module)}.resolve!/1 returned #{scope}, which is not a binary.

    AshVault scope keys must be binaries: they name key material in the provider and are
    bound into every ciphertext's associated data, so they have to be stable across
    processes, releases and OTP upgrades.
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

defmodule AshVault.Errors.OpaqueKeyUnsupported do
  @moduledoc """
  Raised when a key provider returned an opaque `AshVault.Key` handle to a cipher that
  can only work on raw key bytes.

  This is a configuration fault, not a transport failure and emphatically not tampering:
  the pairing of provider and cipher is wrong and will be wrong on every retry. The
  alternative — silently fetching the bytes out of the handle and carrying on — would
  put the key back on the BEAM heap, which is the exact thing the handle exists to
  prevent, so AshVault refuses instead.
  """

  use Splode.Error,
    fields: [:cipher, :provider, :resource, :field, :operation],
    class: :invalid

  def message(%{cipher: cipher, provider: provider} = error) do
    """
    #{inspect(cipher)} cannot use the opaque key handle returned by #{inspect(provider)}#{at(error)}.

    #{inspect(provider)} returned an `%AshVault.Key{}` handle, which keeps key material
    outside the BEAM heap, but #{inspect(cipher)} only accepts raw key bytes.

    Either configure a cipher that understands handles (for example
    `AshVaultRustler.Cipher`), or configure a provider that returns binaries.
    AshVault will not unwrap the handle for you: doing so would copy the key onto the
    BEAM heap, which is the one thing the handle exists to prevent.
    """
  end

  defp at(%{resource: nil}), do: ""

  # The verb follows the operation. Reporting a failed decrypt as "encrypting" is the
  # same defect as REVIEW_FINDINGS #10 — it sends the operator looking at the wrong half
  # of the system.
  defp at(%{resource: resource, field: field, operation: operation}) do
    ", #{verb(operation)} #{inspect(resource)}.#{field}"
  end

  defp verb(:decrypt), do: "decrypting"
  defp verb(_operation), do: "encrypting"
end
