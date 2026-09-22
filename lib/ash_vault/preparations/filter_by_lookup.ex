defmodule AshVault.Preparations.FilterByLookup do
  @moduledoc """
  Backs the generated `:by_<field>` read action: turns the action's plaintext argument
  into a filter on `<field>_lookup`.

  `AshVault.Transformers.SetupEncryption` adds one of these per `searchable?: true`
  field, alongside a `sensitive?: true` argument of the field's own type.

  ## Why a preparation and not a filter expression

  A `filter expr(email_lookup == ^arg(:email))` cannot work: the stored value is an HMAC
  of the *normalized* plaintext under a per-scope key, and there is no expression
  function that can compute one. The token has to be built in Elixir, with the scope
  resolved from the query's tenant, before the filter exists.

  ## Why it adds the error rather than raising

  A preparation runs inside `Ash.Query.for_read/4`. Raising there would make
  `Ash.read/2` — the non-bang form — throw instead of returning `{:error, _}`, which is
  the one place in AshVault an error would escape a non-bang Ash call as an exception.
  `Ash.Query.add_error/2` keeps the contract: `Ash.read/2` returns the error,
  `Ash.read!/2` raises it, and Ash aggregates it like any other `:invalid`-class error.

  What it must never do is filter on nothing and return `{:ok, []}`. An empty result for
  a missing tenant reads as "no such user", which is exactly the answer a login check,
  an availability check or a dedupe pass would act on.
  """

  use Ash.Resource.Preparation

  alias AshVault.Context.Builder

  @doc false
  @impl Ash.Resource.Preparation
  def prepare(query, opts, context) do
    field = Keyword.fetch!(opts, :field)
    value = Ash.Query.get_argument(query, field)

    ash_context = %{
      tenant: Map.get(context, :tenant),
      actor: Map.get(context, :actor),
      source_context: Map.get(context, :source_context) || %{}
    }

    case AshVault.Lookup.token_for(
           query.resource,
           field,
           value,
           Builder.from_query(query, field, ash_context)
         ) do
      {:ok, token} ->
        AshVault.Query.apply_filter(query, AshVault.lookup_field_name(field), token)

      {:error, error} ->
        Ash.Query.add_error(query, error)
    end
  end
end
