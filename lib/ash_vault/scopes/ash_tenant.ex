defmodule AshVault.Scopes.AshTenant do
  @moduledoc """
  Scopes encryption keys to the Ash tenant of the operation.

  The tenant is read from the `:tenant` key of `context.ash_context` and normalised to a
  stable binary by `to_scope_key/1`:

    * a binary is used as-is
    * an atom or integer is stringified
    * a struct with an `:id` is reduced to the stringified id
    * anything else raises `AshVault.Errors.MissingScope` with
      `reason: :unsupported_tenant_shape`

  Stringification (rather than `:erlang.term_to_binary/1`) keeps scope keys readable and
  stable across processes, releases and OTP upgrades.

  When no tenant is present the operator gets an actionable error explaining that the
  resource uses tenant-scoped encryption.
  """

  @behaviour AshVault.Scope

  alias AshVault.Context
  alias AshVault.Errors.MissingScope

  @doc """
  Resolve the tenant of an operation to a stable scope key.

  Raises `AshVault.Errors.MissingScope` when no tenant is present, or when the tenant is
  of a shape AshVault cannot turn into a stable key.
  """
  @impl AshVault.Scope
  @spec resolve!(Context.t()) :: binary()
  def resolve!(%Context{} = context) do
    case tenant(context) do
      nil ->
        raise MissingScope.exception(
                resource: context.resource,
                field: context.field,
                scope_module: __MODULE__,
                reason: :no_tenant
              )

      tenant ->
        to_scope_key(tenant, context)
    end
  end

  @doc """
  Normalise a tenant term into a stable binary scope key.
  """
  @spec to_scope_key(term(), Context.t() | nil) :: binary()
  def to_scope_key(tenant, context \\ nil)

  def to_scope_key(tenant, _context) when is_binary(tenant), do: tenant

  def to_scope_key(tenant, _context) when is_atom(tenant) and not is_nil(tenant),
    do: Atom.to_string(tenant)

  def to_scope_key(tenant, _context) when is_integer(tenant), do: Integer.to_string(tenant)

  def to_scope_key(%_struct{id: id}, context) when not is_nil(id) do
    to_scope_key(id, context)
  end

  def to_scope_key(tenant, context) do
    raise MissingScope.exception(
            resource: context && context.resource,
            field: context && context.field,
            scope_module: __MODULE__,
            reason: :unsupported_tenant_shape,
            vars: [tenant: inspect(tenant)]
          )
  end

  defp tenant(%Context{ash_context: %{tenant: tenant}}), do: tenant
  defp tenant(%Context{}), do: nil
end
