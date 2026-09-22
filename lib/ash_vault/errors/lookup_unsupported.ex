defmodule AshVault.Errors.LookupUnsupported do
  @moduledoc """
  Raised when a lookup token is needed but the key provider cannot supply a lookup key.

  `c:AshVault.KeyProvider.lookup_key/1` is an optional callback, so a provider written
  before searchable fields existed — or a bespoke one — simply does not have it.
  `AshVault.Verifiers.VerifyVault` catches that at compile time whenever it can see the
  provider module, which is the overwhelmingly common case. This error is the runtime
  backstop for the cases it cannot: a provider resolved through a `fun/2` or MFA vault,
  or one that was not yet compiled when the resource was.
  """

  use Splode.Error, fields: [:provider, :resource, :field], class: :invalid

  @doc false
  def message(error) do
    """
    #{inspect(error.provider)} cannot serve lookup tokens for \
    #{inspect(error.resource)}.#{error.field}: it does not implement \
    `AshVault.KeyProvider.lookup_key/1`.

    A searchable field needs a stable, non-rotating, per-scope secret that is separate
    from the encryption key. Implement the optional callback:

        @impl AshVault.KeyProvider
        def lookup_key(scope) do
          # a per-scope secret that `rotate/1` never changes and `destroy/1` erases
        end

    It must NOT be derived from the key `current_key/1` returns. Deriving it from the
    rotating key makes every stored token stop matching the moment the scope is rotated,
    silently.
    """
  end
end
