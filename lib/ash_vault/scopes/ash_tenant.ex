defmodule AshVault.Scopes.AshTenant do
  @moduledoc """
  Scopes encryption keys to the Ash tenant of the operation.

  `context.ash_context` is the raw Ash context — an `Ash.Resource.Change.Context`, an
  `Ash.Resource.Calculation.Context`, or a plain map. The tenant is looked up in order:

    1. the top-level `:tenant` field, which is where both Ash context structs carry it
    2. `source_context[:tenant]`, for contexts whose tenant only reached the source context

  The first non-nil wins. No specific struct module is ever required.

  The tenant is then normalised to a stable binary by `to_scope_key/1`:

    * a binary is used as-is
    * an atom or integer is stringified
    * a struct with an `:id` is reduced to the stringified id
    * anything else raises `AshVault.Errors.MissingScope` with
      `reason: :unsupported_tenant_shape`, whose message says what was received and
      which shapes are accepted — a tenant WAS passed, it just could not be reduced to
      a stable key, and telling the operator to "pass a tenant" would send them hunting
      something that is not missing

  That "what was received" is a **description**, never the tenant itself: see
  `describe_tenant/1`. A tenant is routinely a loaded record full of customer PII, and
  the error it fails with ends up in logs and APM.

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
            tenant: describe_tenant(tenant)
          )
  end

  @doc """
  Describe a tenant term for an operator-facing error, without reproducing its contents.

  `MissingScope`'s `:tenant` field is rendered into `Exception.message/1` and travels
  wherever Ash sends the error — logs, Sentry, an APM trace. A tenant is very often a
  whole loaded record (`%MyApp.Organization{name: ..., billing_email: ...}`), so
  `inspect/2` here would push customer PII into every one of those places to answer a
  question that only needs the *shape*: what did we get, and why could we not reduce it
  to a key?

  Structs are therefore named, not printed, and the description says explicitly whether
  an `:id` was present-but-nil or absent altogether — which is the whole diagnosis.
  """
  @spec describe_tenant(term()) :: binary()
  def describe_tenant(%struct{} = tenant) do
    if Map.has_key?(tenant, :id) do
      "a %#{inspect(struct)}{} whose :id is nil"
    else
      "a %#{inspect(struct)}{}, which has no :id field"
    end
  end

  def describe_tenant(tenant) when is_map(tenant) do
    "a map with keys #{inspect(tenant |> Map.keys() |> Enum.filter(&is_atom/1) |> Enum.sort())}"
  end

  def describe_tenant(tenant) when is_list(tenant), do: "a list of #{length(tenant)} element(s)"
  def describe_tenant(tenant) when is_tuple(tenant), do: "a #{tuple_size(tenant)}-tuple"
  def describe_tenant(tenant) when is_float(tenant), do: "a float"
  def describe_tenant(tenant) when is_pid(tenant), do: "a pid"
  def describe_tenant(tenant) when is_reference(tenant), do: "a reference"
  def describe_tenant(tenant) when is_function(tenant), do: "a function"
  def describe_tenant(_tenant), do: "a term of an unsupported type"

  defp tenant(%Context{ash_context: ash_context})
       when is_map(ash_context) do
    case Map.get(ash_context, :tenant) do
      nil -> get_in(ash_context, [Access.key(:source_context, %{}), :tenant])
      tenant -> tenant
    end
  end

  defp tenant(%Context{}), do: nil
end
