defmodule AshVault.Preparations.PreferVaultCopy do
  @moduledoc """
  The dual-read of an `encrypt ..., legacy: ..., decrypt_for: [...]` field, added by
  `AshVault.Transformers.SetupEncryption` as a global preparation.

  For an actor `decrypt_for` admits, the legacy attribute is replaced by its decrypted
  AshVault copy when the row has one, and left as the legacy value when it does not yet
  (the backfill has not reached it). Any decrypt error — `ProviderUnavailable`,
  `ProviderForbidden`, `KeyDestroyed`, `CiphertextIntegrityFailed` — fails the read: it is
  never answered from the legacy copy. Every other actor keeps the legacy value, subject
  to the resource's field policies.

  Siblings are fetched with a native read using the original action, arguments, actor,
  tenant, public context, filter and lock, bounded to the chunk's primary keys. Native
  preparations and field authorization run again; private state and existing hooks are
  not copied. Missing, duplicate or changed rows fail closed. Pagination has already
  selected the chunk, so its offset/cursor is not applied a second time. Supplied-record
  loads retain `query_for: :load` and cannot acquire fresh-read authority. The context
  marker bounds this preparation to one sibling read per selected field and tenant chunk.

  Skipped:

    * for actor-less reads, so `AshVault.Backfill` verify compares the ciphertext with
      the real legacy column;
    * for the row query of a bulk update or destroy — an `after_action` hook would force
      it off its atomic path, and an offboarding delete would decrypt every row;
    * for its own nested read, marked by context;
    * when the query does not select the legacy attribute.
  """

  use Ash.Resource.Preparation

  require Ash.Query

  @loading :ash_vault_prefer_vault_copy_loading

  @doc false
  @impl Ash.Resource.Preparation
  def prepare(query, opts, context) do
    policy_context =
      AshVault.Context.Builder.from_query(query, opts[:field], context).ash_context
      |> Map.put(:resource, query.resource)
      |> Map.put(:field, opts[:field])

    if skip?(query) or
         not AshVault.DecryptFor.allowed?(
           opts[:decrypt_for],
           context.actor,
           query.action,
           policy_context
         ) do
      query
    else
      Ash.Query.after_action(query, &prefer(&1, &2, opts, context.actor))
    end
  end

  defp skip?(query) do
    query.context[:query_for] in [:bulk_update, :bulk_destroy] or
      query.context[@loading] == true
  end

  defp prefer(query, records, opts, actor) do
    if selected?(query, opts[:field]) do
      records
      |> Enum.chunk_by(&tenant_of(query, &1))
      |> Enum.reduce_while({:ok, []}, &load_chunk(&1, &2, query, opts, actor))
    else
      {:ok, records}
    end
  end

  defp selected?(%{select: nil}, _field), do: true
  defp selected?(%{select: select}, field), do: field in select

  defp tenant_of(%{tenant: nil}, record), do: tenant_attribute(record)
  defp tenant_of(%{tenant: tenant}, _record), do: tenant

  defp tenant_attribute(%resource{} = record) do
    case Ash.Resource.Info.multitenancy_attribute(resource) do
      nil -> nil
      attribute -> Map.get(record, attribute)
    end
  end

  defp load_chunk(chunk, {:ok, acc}, query, opts, actor) do
    vault_field = opts[:vault_field]
    tenant = tenant_of(query, hd(chunk))

    load_query =
      query.resource
      |> Ash.Query.set_domain(query.domain)
      |> Ash.Query.set_context(Map.drop(query.context, [:private]))
      |> Ash.Query.set_context(%{@loading => true})
      |> Ash.Query.for_read(query.action.name, query.arguments, actor: actor, tenant: tenant)
      |> Ash.Query.load(vault_field)

    case retrieve(chunk, load_query, query, opts) do
      {:ok, loaded} ->
        {:cont, {:ok, acc ++ Enum.map(loaded, &swap(&1, opts[:field], vault_field))}}

      {:error, error} ->
        {:halt, {:error, error}}
    end
  end

  defp retrieve(chunk, load_query, query, opts) do
    primary_key = Ash.Resource.Info.primary_key(query.resource)
    keys = Enum.map(chunk, &Map.take(&1, primary_key))

    if primary_key == [] or query.combination_of != [] or not valid_keys?(keys, primary_key) do
      forbidden()
    else
      load_query =
        load_query
        |> Ash.Query.filter(^query.filter)
        |> Ash.Query.filter(^[or: keys])
        |> Ash.Query.select(query.select || Ash.Resource.Info.attribute_names(query.resource))

      load_query = %{
        load_query
        | sort: query.sort,
          distinct: query.distinct,
          distinct_sort: query.distinct_sort,
          limit:
            Enum.min([
              length(chunk),
              query.limit || length(chunk),
              load_query.limit || length(chunk)
            ]),
          offset: 0,
          lock: query.lock
      }

      page = if load_query.action.pagination, do: [limit: length(chunk)], else: false

      with {:ok, result} <- Ash.read(load_query, page: page) do
        loaded = if is_list(result), do: result, else: result.results
        match_records(chunk, loaded, primary_key, query, opts)
      end
    end
  end

  defp match_records(chunk, loaded, primary_key, query, opts) do
    by_key = Map.new(loaded, &{Map.take(&1, primary_key), &1})
    legacy_fields = Enum.map(AshVault.Info.legacy_fields(query.resource), & &1.name)

    attributes =
      (query.select || Ash.Resource.Info.attribute_names(query.resource))
      |> Enum.reject(&(&1 in legacy_fields and &1 != opts[:field]))

    if length(loaded) == length(chunk) and map_size(by_key) == length(chunk) do
      Enum.reduce_while(chunk, {:ok, []}, fn record, {:ok, acc} ->
        case Map.fetch(by_key, Map.take(record, primary_key)) do
          {:ok, fresh} ->
            if Enum.all?(attributes, &(Map.get(record, &1) == Map.get(fresh, &1))) and
                 not is_struct(Map.fetch!(fresh, opts[:vault_field]), Ash.NotLoaded) do
              {:cont,
               {:ok,
                [Map.put(record, opts[:vault_field], Map.fetch!(fresh, opts[:vault_field])) | acc]}}
            else
              {:halt, forbidden()}
            end

          :error ->
            {:halt, forbidden()}
        end
      end)
      |> case do
        {:ok, records} -> {:ok, Enum.reverse(records)}
        error -> error
      end
    else
      forbidden()
    end
  end

  defp valid_keys?(keys, primary_key) do
    Enum.all?(keys, fn key ->
      map_size(key) == length(primary_key) and
        Enum.all?(Map.values(key), fn value ->
          not is_nil(value) and not is_struct(value, Ash.NotLoaded) and
            not is_struct(value, Ash.ForbiddenField)
        end)
    end)
  end

  defp forbidden, do: {:error, Ash.Error.Forbidden.exception([])}

  defp swap(record, field, vault_field) do
    case Map.fetch!(record, vault_field) do
      nil -> record
      plaintext -> Map.put(record, field, plaintext)
    end
  end
end
