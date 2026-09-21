defmodule AshVault.Test.Support.Resources do
  @moduledoc """
  Plain module names standing in for Ash resources in crypto-core tests.

  The crypto core only ever puts the resource module into the AAD via `inspect/1`, so
  these need no behaviour of their own.
  """

  defmodule User do
    @moduledoc "Stand-in resource used in AshVault crypto-core tests."
  end

  defmodule Invoice do
    @moduledoc "Second stand-in resource, for cross-resource AAD tests."
  end
end

defmodule AshVault.Test.Support.TenantVault do
  @moduledoc """
  Tenant-scoped test vault backed by the default-named in-memory key provider.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.Memory
end

defmodule AshVault.Test.Support.GlobalVault do
  @moduledoc """
  Globally-scoped test vault backed by the default-named in-memory key provider.
  """

  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    scope: AshVault.Scopes.Global
end

defmodule AshVault.Test.Support.Helpers do
  @moduledoc """
  Helpers shared by the AshVault crypto-core test suites.
  """

  alias AshVault.Test.Support.Resources

  @doc """
  Build an `AshVault.Context` with sensible test defaults.
  """
  @spec context(keyword()) :: AshVault.Context.t()
  def context(opts \\ []) do
    %AshVault.Context{
      resource: Keyword.get(opts, :resource, Resources.User),
      field: Keyword.get(opts, :field, :ssn),
      ash_context: Keyword.get(opts, :ash_context, %{tenant: "acme", actor: nil, context: %{}})
    }
  end

  @doc """
  Build an `AshVault.Context` for a given tenant.
  """
  @spec context_for(term(), keyword()) :: AshVault.Context.t()
  def context_for(tenant, opts \\ []) do
    opts
    |> Keyword.put(:ash_context, %{tenant: tenant, actor: nil, context: %{}})
    |> context()
  end
end
