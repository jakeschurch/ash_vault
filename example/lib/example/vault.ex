defmodule Example.Vault do
  @moduledoc """
  The example's vault: key provider + cipher + envelope + key scope + rotation policy.

  A vault is a compile-time bundle, so switching key providers means switching vault
  module. The two vaults below are identical apart from their provider, and
  `Example.Vault.current/0` picks between them from config — which is why every
  resource declares its vault as the `fun/2` form
  `&Example.Vault.resolve/2` rather than naming a module directly.

  For a real application you would name one vault module and be done; the indirection
  here exists only so this example can demonstrate both providers.
  """

  @doc """
  The vault the example is currently configured to use.

  `ASHVAULT_PROVIDER=local` selects `Example.Vault.Local` (key material in a directory
  on disk); anything else selects `Example.Vault.Bao` (key material in OpenBao transit).
  """
  @spec current() :: module()
  def current do
    case Application.get_env(:example, :key_provider, "openbao") do
      "local" -> Example.Vault.Local
      _ -> Example.Vault.Bao
    end
  end

  @doc """
  The `fun/2` vault form the resources declare.

  AshVault calls this on the write path, the read path and the key-lifecycle actions
  alike, always with the normalized `ash_context` map.
  """
  @spec resolve(module() | Spark.Dsl.t(), term()) :: module()
  def resolve(_resource, _context), do: current()

  @doc "The key provider module behind the current vault."
  @spec key_provider() :: module()
  def key_provider, do: current().__ash_vault__(:key_provider)
end

defmodule Example.Vault.Bao do
  @moduledoc """
  Keys in OpenBao transit — the production-shaped configuration.

  Nothing key-related is ever written to PostgreSQL, so a database dump contains no
  key material and restoring one cannot undo a crypto-erasure. Erasure is a DELETE of
  the transit key plus a tombstone in a KV-v2 mount, both of which live outside the
  `pg_dump` domain entirely.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.OpenBao
end

defmodule Example.Vault.Local do
  @moduledoc """
  Keys in a directory on disk — the single-node configuration.

  It satisfies the same property as OpenBao for a weaker reason: the key root is a
  *different system* from the database, so long as it is genuinely excluded from the
  database backup job. Put both in one tarball and the guarantee is gone.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
end
