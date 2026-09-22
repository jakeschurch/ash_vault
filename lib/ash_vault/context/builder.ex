defmodule AshVault.Context.Builder do
  @moduledoc """
  Builds `%AshVault.Context{}` values at the Ash boundary — the only place they are
  constructed.

  The two Ash callback context structs are different shapes and neither is something the
  crypto core should have to pattern-match:

      Ash.Resource.Change.Context       [:actor, :tenant, :authorize?, :tracer,
                                         bulk?: false, source_context: %{}]
      Ash.Resource.Calculation.Context  [:actor, :tenant, :authorize?, :tracer, :domain,
                                         :resource, :type, :constraints, :arguments,
                                         source_context: %{}]

  So both are normalized to one plain map before being put in `:ash_context`:

      %{tenant: tenant, actor: actor, source_context: source_context, phase: :write | :read}

  Three traps this module exists to handle:

    1. **`source_context` is stale inside a change.** It is snapshotted once during
       `for_create`/`for_update`; only `tenant` is refreshed per change. Anything a caller
       sets with `Ash.Changeset.set_context/2` afterwards never reaches `change/3`, so
       `AshVault.Changes.Encrypt` rebuilds it from `changeset.context` inside the hook.
    2. **On the write path `changeset.tenant` wins** — it is authoritative and current. On
       the read path the calculation context's `:tenant` wins, falling back to
       `source_context[:private][:tenant]`, which is the same fallback Ash's own
       calculation builder uses.
    3. **The tenant here is the RAW tenant**, never normalized through `Ash.ToTenant` — it
       may be a whole `%Organization{}` struct. Normalizing it to a stable binary scope key
       is `AshVault.Scopes.AshTenant`'s job.

  There is no `context \\\\ nil` default anywhere: a missing tenant is not a fallback, it
  is `AshVault.Errors.MissingScope`.

  > #### Deviation from the spec {: .info}
  >
  > EXTENSION_SPEC §4 puts these constructors on `AshVault.Context` itself. They live here
  > instead so the crypto-core module — which must not depend on Ash at runtime — stays
  > free of Ash references.
  """

  alias AshVault.Context

  @doc """
  Build a context for the write path from a changeset and the change callback context.
  """
  @spec from_changeset(Ash.Changeset.t(), atom(), map()) :: Context.t()
  def from_changeset(changeset, field, ash_context) do
    %Context{
      resource: changeset.resource,
      field: field,
      ash_context: %{
        tenant: changeset.tenant || Map.get(ash_context, :tenant),
        actor: Map.get(ash_context, :actor),
        source_context: source_context(ash_context, changeset.context),
        phase: :write
      }
    }
  end

  @doc """
  Build a context for the read path from a resource and the calculation callback context.
  """
  @spec from_calculation(module(), atom(), map()) :: Context.t()
  def from_calculation(resource, field, ash_context) do
    source_context = source_context(ash_context, %{})

    %Context{
      resource: resource,
      field: field,
      ash_context: %{
        tenant: Map.get(ash_context, :tenant) || private_tenant(source_context),
        actor: Map.get(ash_context, :actor),
        source_context: source_context,
        phase: :read
      }
    }
  end

  @doc """
  Build a context for a lookup-token computation from a query.

  `query.tenant` wins, for the same reason `changeset.tenant` wins on the write path: it
  is authoritative and current, while a callback context's copy was snapshotted earlier.
  That symmetry is what makes a lookup resolve the *same* scope the matching write did —
  and therefore what makes a query with no tenant raise `AshVault.Errors.MissingScope`
  exactly as the write would, instead of filtering on a token nobody stored and
  returning zero rows.
  """
  @spec from_query(Ash.Query.t(), atom(), map()) :: Context.t()
  def from_query(query, field, ash_context) do
    source_context = source_context(ash_context, query.context || %{})

    %Context{
      resource: query.resource,
      field: field,
      ash_context: %{
        tenant: query.tenant || Map.get(ash_context, :tenant) || private_tenant(source_context),
        actor: Map.get(ash_context, :actor),
        source_context: source_context,
        phase: :read
      }
    }
  end

  @doc """
  Build a context for a generic lifecycle action from its input and callback context.

  `Ash.Resource.Actions.Implementation.Context` has no `:resource`, so the resource comes
  from `input.resource`.
  """
  @spec from_action_input(Ash.ActionInput.t(), map()) :: Context.t()
  def from_action_input(input, ash_context) do
    source_context = source_context(ash_context, input.context || %{})

    %Context{
      resource: input.resource,
      field: :__key_lifecycle__,
      ash_context: %{
        tenant: input.tenant || Map.get(ash_context, :tenant) || private_tenant(source_context),
        actor: Map.get(ash_context, :actor),
        source_context: source_context,
        phase: :write
      }
    }
  end

  defp source_context(ash_context, fallback) do
    case Map.get(ash_context, :source_context) do
      nil -> fallback || %{}
      source_context -> source_context
    end
  end

  defp private_tenant(source_context) when is_map(source_context) do
    case Map.get(source_context, :private) do
      private when is_map(private) -> Map.get(private, :tenant)
      _other -> nil
    end
  end

  defp private_tenant(_source_context), do: nil
end
