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

  Skipped:

    * for actor-less reads, so `AshVault.Backfill` verify compares the ciphertext with
      the real legacy column;
    * for the row query of a bulk update or destroy — an `after_action` hook would force
      it off its atomic path, and an offboarding delete would decrypt every row;
    * for its own nested `Ash.load/3`, marked by context;
    * when the query does not select the legacy attribute.
  """

  use Ash.Resource.Preparation

  @loading :ash_vault_prefer_vault_copy_loading

  @doc false
  @impl Ash.Resource.Preparation
  def prepare(query, opts, context) do
    if skip?(query) or
         not AshVault.DecryptFor.allowed?(opts[:decrypt_for], context.actor, query.action) do
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

    case Ash.load(chunk, [vault_field],
           actor: actor,
           tenant: tenant_of(query, hd(chunk)),
           context: %{@loading => true}
         ) do
      {:ok, loaded} ->
        {:cont, {:ok, acc ++ Enum.map(loaded, &swap(&1, opts[:field], vault_field))}}

      {:error, error} ->
        {:halt, {:error, error}}
    end
  end

  defp swap(record, field, vault_field) do
    case Map.fetch!(record, vault_field) do
      nil -> record
      plaintext -> Map.put(record, field, plaintext)
    end
  end
end
