defmodule AshVault.Macaroon.Actions.Mint do
  @moduledoc """
  Backs the generated `:mint_<name>` generic action.

  Loads the record named by the identity argument through the resource's primary read
  action (same actor, tenant and `authorize?` as the mint), refuses a missing or revoked
  record, then signs. Arguments:

    * the identity attribute (`identity` in the DSL) — which record the token names
    * `:caveats` — a map of declared caveat names to values, cast to each caveat's type
    * `:ttl` — seconds, overriding `default_ttl`; refused above `max_ttl`

  A function `default_ttl` is called with this action's input, and its answer clamped to
  `max_ttl`.

  Returns the token string. The token is a bearer credential: it is returned once and
  never stored by AshVault.
  """

  use Ash.Resource.Actions.Implementation

  alias AshVault.Macaroon.Record
  alias AshVault.Macaroon.Runtime

  @impl Ash.Resource.Actions.Implementation
  def run(input, opts, context) do
    resource = input.resource
    definition = AshVault.Info.macaroon(resource, Keyword.fetch!(opts, :macaroon))
    attribute = Runtime.identity_attribute(resource, definition)
    value = Ash.ActionInput.get_argument(input, attribute.name)

    with {:ok, record} <- load(resource, definition, attribute, value, input, context),
         {:ok, id} <- encode_id(record, attribute),
         {:ok, caveats} <- cast_caveats(definition, Ash.ActionInput.get_argument(input, :caveats)) do
      Runtime.mint(resource, definition, id, caveats,
        tenant: input.tenant,
        actor: context.actor,
        source_context: input.context,
        ttl: Ash.ActionInput.get_argument(input, :ttl),
        input: input
      )
    end
  end

  defp load(resource, definition, attribute, value, input, context) do
    read = Ash.Resource.Info.primary_action!(resource, :read)

    resource
    |> Ash.Query.for_read(read.name, %{},
      actor: context.actor,
      tenant: input.tenant,
      authorize?: context.authorize?,
      domain: input.domain
    )
    |> Record.filter_identity(attribute, value)
    |> Record.with_revocation(definition)
    |> Ash.read_one()
    |> case do
      {:ok, nil} ->
        {:error, Ash.Error.Query.NotFound.exception(resource: resource)}

      {:ok, record} ->
        if Record.revoked?(record, definition),
          do: {:error, Runtime.revoked(resource, definition, :record)},
          else: {:ok, record}

      {:error, error} ->
        {:error, error}
    end
  end

  defp encode_id(record, attribute) do
    case Runtime.encode_id(Map.get(record, attribute.name)) do
      {:ok, id} ->
        {:ok, id}

      :error ->
        {:error,
         Ash.Error.Action.InvalidArgument.exception(
           field: attribute.name,
           message: "cannot encode identity"
         )}
    end
  end

  defp cast_caveats(_definition, nil), do: {:ok, []}

  defp cast_caveats(definition, caveats) when is_map(caveats) do
    given = Map.new(caveats, fn {name, value} -> {to_string(name), value} end)
    declared = MapSet.new(definition.caveats, &Atom.to_string(&1.name))

    case Enum.reject(Map.keys(given), &MapSet.member?(declared, &1)) do
      [] ->
        definition.caveats
        |> Enum.filter(&Map.has_key?(given, Atom.to_string(&1.name)))
        |> Enum.reduce_while({:ok, []}, fn caveat, {:ok, acc} ->
          case Ash.Type.cast_input(
                 caveat.type,
                 given[Atom.to_string(caveat.name)],
                 caveat.constraints
               ) do
            {:ok, value} when not is_nil(value) ->
              {:cont, {:ok, [{caveat.name, value} | acc]}}

            _error ->
              {:halt,
               {:error, invalid_caveats("caveat #{inspect(caveat.name)} has an invalid value")}}
          end
        end)
        |> case do
          {:ok, cast} -> {:ok, Enum.reverse(cast)}
          error -> error
        end

      unknown ->
        {:error, invalid_caveats("undeclared caveats: #{Enum.join(unknown, ", ")}")}
    end
  end

  defp invalid_caveats(message),
    do: Ash.Error.Action.InvalidArgument.exception(field: :caveats, message: message)
end
