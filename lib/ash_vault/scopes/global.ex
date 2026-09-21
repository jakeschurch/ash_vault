defmodule AshVault.Scopes.Global do
  @moduledoc """
  A constant encryption scope, `"global"`, for applications that are not multitenant.

  Every encrypted field in the application shares one key lineage, which means rotation
  and destruction are also application-wide. Use `AshVault.Scopes.AshTenant` if you need
  per-tenant crypto-erasure.
  """

  @behaviour AshVault.Scope

  @scope "global"

  @doc """
  Always resolves to `"global"`.
  """
  @impl AshVault.Scope
  @spec resolve!(AshVault.Context.t()) :: binary()
  def resolve!(%AshVault.Context{}), do: @scope
end
