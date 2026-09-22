defmodule AshVault.Backfill do
  @moduledoc """
  The online backfill engine behind `mix ash_vault.backfill` and `mix ash_vault.verify`.

  It turns an existing plaintext column into ciphertext in the resource's
  `encrypted_<field>` column, one committed batch at a time, and never wraps the whole
  table in a transaction.

  The Mix tasks are thin argument-parsing shells over `run/3`; everything that matters —
  planning, the provider pre-flight, keyset paging, the AAD, verification — lives here so
  it can be called from a release without Mix.

      AshVault.Backfill.run(MyApp.Accounts.User, :email, tenant: "acme", from: :legacy_email)

  ## Why it is idempotent and resumable with no state file

  Every batch is selected with `encrypted_<field> IS NULL`, ordered by primary key, paged
  with a keyset (`pk > last_seen`) rather than `OFFSET`. A row that has already been
  encrypted no longer matches the filter, so a re-run after a crash — or after a provider
  outage half way through — simply picks up the rows that are still NULL. `--resume-from`
  is an optimisation that skips re-scanning the committed prefix, never a correctness
  requirement.

  When the field is configured `encrypt_nil?: false`, a `nil` source value legitimately
  stores SQL NULL in the encrypted column. Those rows would match the NULL filter forever,
  so they are excluded with `source IS NOT NULL` and reported as `skipped_nil_source`.

  ## Why backfilled rows decrypt through the ordinary read path

  The associated data bound into every AshVault ciphertext is
  `scope | resource | field`, and the scope comes from the Ash tenant. A backfill that
  built its own context by hand would be one field name away from writing rows that never
  decrypt again, so the context is built by `AshVault.Context.Builder.from_changeset/3` —
  the same function `AshVault.Changes.Encrypt` calls on an ordinary write — from a real
  changeset over the real record, with the plaintext *field* name (`:email`), never the
  ciphertext attribute name.

  ## The write

  One `Ash.bulk_update/4` per batch, `strategy: [:stream]`, `transaction: :all` (so the
  batch, and only the batch, is a transaction), `return_records?: false`, `authorize?:
  false` and `skip_unknown_inputs: :*`. The per-row ciphertext is applied through the
  `:transform_changeset` hook — a single bulk `input` map cannot carry a different
  ciphertext per row — and it is the *only* attribute touched.

  Because `strategy: [:stream]` cannot run an update action declared
  `require_atomic? true`, `plan/3` rejects such an action up front with a message naming
  `--action`, rather than letting Ash's `NoMatchingBulkStrategy` leak out of a batch.

  ## Progress reporting

  Pass a `:reporter` — a one-argument function receiving `{event, payload}` tuples:

    * `{:preflight, map}` — resource, field, source, scope, provider, total rows, batch size
    * `{:batch, map}` — batch number, rows, done, remaining, rate, ETA, elapsed
    * `{:done, map}` — final counts
    * `{:verify_sample, map}` / `{:verify_done, map}` — verification progress and result
  """

  alias AshVault.Context.Builder
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.Vault.Runtime

  @default_batch_size 500
  @max_verify_sample 1000

  @typedoc "A planned backfill: everything `run/3` needs, fully resolved and validated."
  @type plan :: %{
          resource: module(),
          field: atom(),
          encrypted_field: atom(),
          source: atom(),
          primary_key: atom(),
          tenant: term(),
          domain: module() | nil,
          action: atom(),
          batch_size: pos_integer(),
          dry_run?: boolean(),
          resume_from: term(),
          sample: non_neg_integer() | nil,
          encrypt_nil?: boolean(),
          vault: module(),
          scope: term(),
          provider: module(),
          reporter: (term() -> any())
        }

  @doc """
  Plan and validate a backfill without touching the database or the key provider.

  Returns `{:ok, plan}` or `{:error, %ArgumentError{}}` naming the missing piece.
  """
  @spec plan(module(), atom(), keyword()) :: {:ok, plan()} | {:error, Exception.t()}
  def plan(resource, field, opts \\ []) do
    with :ok <- ensure_extension(resource),
         {:ok, encrypted} <- fetch_encrypted_field(resource, field),
         {:ok, source} <- fetch_source(resource, field, encrypted, opts),
         {:ok, primary_key} <- fetch_primary_key(resource),
         {:ok, action} <- fetch_action(resource, opts),
         {:ok, vault, scope} <- resolve_vault(resource, field, opts[:tenant]) do
      {:ok,
       %{
         resource: resource,
         field: field,
         encrypted_field: AshVault.encrypted_field_name(field),
         source: source,
         primary_key: primary_key,
         tenant: opts[:tenant],
         domain: opts[:domain],
         action: action,
         batch_size: opts[:batch_size] || @default_batch_size,
         dry_run?: !!opts[:dry_run?],
         resume_from: opts[:resume_from],
         sample: opts[:sample],
         encrypt_nil?: AshVault.Info.encrypt_nil?(resource, field),
         vault: vault,
         scope: scope,
         provider: vault.__ash_vault__(:key_provider),
         reporter: opts[:reporter] || fn _event -> :ok end
       }}
    end
  end

  @doc """
  Back-fill `field` on `resource`, or verify it when `verify?: true`.

  Options: `:from`, `:tenant`, `:domain`, `:action`, `:batch_size`, `:resume_from`,
  `:sample`, `:dry_run?`, `:verify?`, `:reporter`.

  Returns `{:ok, stats}`, or `{:error, exception, stats}` when a batch failed — `stats`
  then carries `:resume_from`, the last primary key that was successfully committed.
  """
  @spec run(module(), atom(), keyword()) ::
          {:ok, map()} | {:error, Exception.t()} | {:error, Exception.t(), map()}
  def run(resource, field, opts \\ []) do
    with {:ok, plan} <- plan(resource, field, opts),
         {:ok, key_status} <- check_provider(plan),
         {:ok, total} <- count_pending(plan) do
      report(plan, {:preflight, preflight_payload(plan, total, key_status)})

      if opts[:verify?] do
        verify(plan)
      else
        backfill(plan, total)
      end
    end
  end

  @doc """
  Check that the key provider is reachable for this plan's scope *before* any row is
  written.

  Returns `{:ok, :ready | {:current, version}}`. A dry run only probes (it must never
  mint key material); a real run resolves the current key, minting version 1 on first use
  exactly as an ordinary write would.
  """
  @spec check_provider(plan()) :: {:ok, term()} | {:error, Exception.t()}
  def check_provider(%{provider: provider, scope: scope} = plan) do
    ctx = context(plan)

    case provider.get_key(scope, 1) do
      {:error, :destroyed} ->
        {:error, KeyDestroyed.exception(scope: scope, key_version: nil)}

      {:error, :not_found} when plan.dry_run? ->
        {:ok, :not_minted}

      {:error, reason} when reason not in [:not_found] ->
        {:error, provider_error(provider, Runtime.map_provider_error(reason, scope, ctx))}

      _ ->
        case provider.current_key(scope) do
          {:ok, %{version: version}} ->
            {:ok, {:current, version}}

          {:error, reason} ->
            {:error, provider_error(provider, Runtime.map_provider_error(reason, scope, ctx))}
        end
    end
  end

  @doc """
  Count the rows still needing a backfill under this plan's filter.
  """
  @spec count_pending(plan()) :: {:ok, non_neg_integer()} | {:error, Exception.t()}
  def count_pending(plan) do
    plan
    |> pending_query()
    |> Ash.count(read_opts(plan))
  rescue
    error -> {:error, translate_read_error(error, plan)}
  end

  # -- backfill ---------------------------------------------------------------

  defp backfill(plan, total) do
    stats = %{
      total: total,
      done: 0,
      skipped_nil_source: 0,
      batches: 0,
      dry_run?: plan.dry_run?,
      started_at: System.monotonic_time(:millisecond),
      resume_from: plan.resume_from
    }

    case batch_loop(plan, plan.resume_from, stats) do
      {:ok, stats} ->
        stats = finalize(stats)
        report(plan, {:done, stats})
        {:ok, stats}

      {:error, error, stats} ->
        {:error, error, finalize(stats)}
    end
  end

  defp batch_loop(plan, last_pk, stats) do
    case read_batch(plan, last_pk) do
      {:error, error} ->
        {:error, error, stats}

      {:ok, []} ->
        {:ok, stats}

      {:ok, records} ->
        case encrypt_batch(plan, records) do
          {:error, error} ->
            {:error, error, stats}

          {:ok, blobs, skipped} ->
            case write_batch(plan, records, blobs) do
              {:error, error} ->
                {:error, error, stats}

              :ok ->
                last_pk = Map.fetch!(List.last(records), plan.primary_key)

                stats = %{
                  stats
                  | done: stats.done + map_size(blobs),
                    skipped_nil_source: stats.skipped_nil_source + skipped,
                    batches: stats.batches + 1,
                    resume_from: last_pk
                }

                report(plan, {:batch, batch_payload(plan, stats, length(records))})

                if length(records) < plan.batch_size do
                  {:ok, stats}
                else
                  batch_loop(plan, last_pk, stats)
                end
            end
        end
    end
  end

  defp read_batch(plan, last_pk) do
    plan
    |> pending_query(last_pk)
    |> Ash.Query.sort([{plan.primary_key, :asc}])
    |> Ash.Query.limit(plan.batch_size)
    |> Ash.Query.select([plan.primary_key, plan.source, plan.encrypted_field])
    |> Ash.read(read_opts(plan))
  rescue
    error -> {:error, translate_read_error(error, plan)}
  end

  defp encrypt_batch(%{dry_run?: true} = plan, records) do
    # A dry run must not mint key material either: `encrypt_value/4` would call
    # `current_key/1`, which mints version 1 on first use for a scope that has never been
    # written to. Reporting what *would* happen needs no ciphertext.
    {:ok, Map.new(records, &{Map.fetch!(&1, plan.primary_key), :dry_run}), 0}
  end

  defp encrypt_batch(plan, records) do
    Enum.reduce_while(records, {:ok, %{}, 0}, fn record, {:ok, blobs, skipped} ->
      value = Map.fetch!(record, plan.source)

      if is_nil(value) and not plan.encrypt_nil? do
        {:cont, {:ok, blobs, skipped + 1}}
      else
        case AshVault.encrypt_value(plan.resource, plan.field, value, context(plan, record)) do
          {:ok, nil} ->
            {:cont, {:ok, blobs, skipped + 1}}

          {:ok, blob} ->
            {:cont, {:ok, Map.put(blobs, Map.fetch!(record, plan.primary_key), blob), skipped}}

          {:error, error} ->
            {:halt, {:error, error}}
        end
      end
    end)
  end

  defp write_batch(_plan, _records, blobs) when map_size(blobs) == 0, do: :ok

  defp write_batch(%{dry_run?: true}, _records, _blobs), do: :ok

  defp write_batch(plan, records, blobs) do
    records = Enum.filter(records, &Map.has_key?(blobs, Map.fetch!(&1, plan.primary_key)))

    result =
      Ash.bulk_update(
        records,
        plan.action,
        %{},
        [
          resource: plan.resource,
          strategy: [:stream],
          transaction: :all,
          return_records?: false,
          return_errors?: true,
          stop_on_error?: true,
          notify?: false,
          authorize?: false,
          skip_unknown_inputs: :*,
          transform_changeset: fn changeset ->
            pk = Map.fetch!(changeset.data, plan.primary_key)

            Ash.Changeset.force_change_attribute(
              changeset,
              plan.encrypted_field,
              Map.fetch!(blobs, pk)
            )
          end
        ] ++ read_opts(plan)
      )

    case result do
      %Ash.BulkResult{status: :success} -> :ok
      %Ash.BulkResult{errors: [error | _]} -> {:error, error}
      %Ash.BulkResult{} = other -> {:error, Ash.Error.to_error_class(other.errors || [])}
    end
  rescue
    error -> {:error, error}
  end

  # -- verify -----------------------------------------------------------------

  @doc """
  Decrypt a sample of backfilled rows and compare them against the plaintext column.

  The sample is 10% of the rows or #{@max_verify_sample}, whichever is smaller, always
  including the first and the last row. `sample: 0` checks every row.

  Rows are paged with the same keyset as the backfill, and only the sampled rows are
  decrypted, so verification costs one table scan and `sample` provider round-trips.
  """
  @spec verify(plan()) :: {:ok, map()} | {:error, Exception.t(), map()}
  def verify(plan) do
    query =
      plan.resource
      |> Ash.Query.new()
      |> Ash.Query.sort([{plan.primary_key, :asc}])
      |> Ash.Query.select([plan.primary_key, plan.source, plan.encrypted_field])

    with {:ok, total} <- safe_count(plan) do
      stride = stride(total, plan.sample)

      {mismatches, checked, _scanned} =
        query
        |> Ash.stream!(Keyword.merge(read_opts(plan), batch_size: plan.batch_size))
        |> Enum.reduce({[], 0, 0}, fn record, {mismatches, checked, scanned} ->
          index = scanned + 1

          if sample?(index, total, stride) do
            case check_row(plan, record) do
              :ok -> {mismatches, checked + 1, index}
              {:mismatch, detail} -> {[detail | mismatches], checked + 1, index}
            end
          else
            {mismatches, checked, index}
          end
        end)

      mismatches = Enum.reverse(mismatches)

      stats = %{total: total, checked: checked, mismatches: mismatches, verify?: true}
      report(plan, {:verify_done, stats})

      if mismatches == [] do
        {:ok, stats}
      else
        {:error, verification_failed(plan, mismatches), stats}
      end
    end
  end

  defp safe_count(plan) do
    plan.resource
    |> Ash.Query.new()
    |> Ash.count(read_opts(plan))
  rescue
    error -> {:error, translate_read_error(error, plan)}
  end

  defp stride(_total, 0), do: 1
  defp stride(total, nil), do: stride_for(total, min(@max_verify_sample, div(total, 10)))
  defp stride(total, sample), do: stride_for(total, sample)

  defp stride_for(_total, sample) when sample <= 0, do: :first_and_last
  defp stride_for(total, sample), do: max(1, div(total, sample))

  defp sample?(index, total, :first_and_last), do: index == 1 or index == total
  defp sample?(index, total, stride), do: index == 1 or index == total or rem(index, stride) == 0

  defp check_row(plan, record) do
    pk = Map.fetch!(record, plan.primary_key)
    expected = Map.fetch!(record, plan.source)

    case Map.fetch!(record, plan.encrypted_field) do
      nil ->
        if is_nil(expected) and not plan.encrypt_nil? do
          :ok
        else
          {:mismatch, %{primary_key: pk, reason: :not_backfilled}}
        end

      blob ->
        %{type: type, constraints: constraints} =
          Ash.Resource.Info.calculation(plan.resource, plan.field)

        case AshVault.decrypt_value(plan.vault, blob, read_context(plan), type, constraints) do
          {:ok, ^expected} ->
            :ok

          # The decrypted value is deliberately NOT carried in the mismatch: `:value_mismatch`
          # already says what went wrong, and `mismatches` is returned to the caller inside
          # `stats`, where one `Logger.error(inspect(stats))` would dump the plaintext of
          # every mismatched row. Nothing consumed it.
          {:ok, _actual} ->
            {:mismatch, %{primary_key: pk, reason: :value_mismatch}}

          {:error, error} ->
            {:mismatch, %{primary_key: pk, reason: :decrypt_failed, error: error}}
        end
    end
  end

  defp verification_failed(plan, mismatches) do
    ArgumentError.exception(
      message: """
      Verification failed for #{inspect(plan.resource)}.#{plan.field}: \
      #{length(mismatches)} row(s) did not match #{inspect(plan.source)}.

      #{mismatches |> Enum.take(10) |> Enum.map_join("\n", &"  #{inspect(&1.primary_key)} #{&1.reason}")}
      """
    )
  end

  # -- queries and contexts ---------------------------------------------------

  @doc """
  The query selecting rows that still need encrypting, optionally after `last_pk`.
  """
  @spec pending_query(plan(), term()) :: Ash.Query.t()
  def pending_query(plan, last_pk \\ nil) do
    plan.resource
    |> Ash.Query.new()
    |> Ash.Query.do_filter([{plan.encrypted_field, [is_nil: true]}])
    |> then(fn query ->
      if plan.encrypt_nil? do
        query
      else
        Ash.Query.do_filter(query, [{plan.source, [is_nil: false]}])
      end
    end)
    |> then(fn query ->
      last_pk = last_pk || plan.resume_from

      if is_nil(last_pk) do
        query
      else
        Ash.Query.do_filter(query, [{plan.primary_key, [greater_than: last_pk]}])
      end
    end)
  end

  @doc """
  Build the write-path `%AshVault.Context{}` for a row, exactly as an ordinary create or
  update would.
  """
  @spec context(plan(), Ash.Resource.record() | nil) :: AshVault.Context.t()
  def context(plan, record \\ nil) do
    changeset =
      case record do
        nil -> Ash.Changeset.new(struct(plan.resource))
        record -> Ash.Changeset.new(record)
      end

    changeset = Ash.Changeset.set_tenant(changeset, plan.tenant)

    Builder.from_changeset(changeset, plan.field, %{
      tenant: plan.tenant,
      actor: nil,
      source_context: %{}
    })
  end

  defp read_context(plan) do
    Builder.from_calculation(plan.resource, plan.field, %{
      tenant: plan.tenant,
      actor: nil,
      source_context: %{}
    })
  end

  defp read_opts(plan) do
    [authorize?: false]
    |> maybe_put(:tenant, plan.tenant)
    |> maybe_put(:domain, plan.domain)
  end

  defp maybe_put(opts, _key, nil), do: opts
  defp maybe_put(opts, key, value), do: Keyword.put(opts, key, value)

  # -- validation -------------------------------------------------------------

  defp ensure_extension(resource) do
    if Code.ensure_loaded?(resource) and
         function_exported?(resource, :spark_dsl_config, 0) and
         AshVault in Spark.extensions(resource) do
      :ok
    else
      {:error,
       ArgumentError.exception(
         message:
           "#{inspect(resource)} is not an Ash resource using the `AshVault` extension. " <>
             "Add `extensions: [AshVault]` and an `ash_vault do ... end` section."
       )}
    end
  end

  defp fetch_encrypted_field(resource, field) do
    case AshVault.Info.encrypted_field(resource, field) do
      nil ->
        {:error,
         ArgumentError.exception(
           message:
             "#{inspect(resource)}.#{field} is not configured under `ash_vault`. " <>
               "Add `encrypt #{inspect(field)}` to the resource's `ash_vault` section. " <>
               "Known encrypted fields: " <>
               inspect(AshVault.Info.encrypted_field_names(resource))
         )}

      encrypted ->
        {:ok, encrypted}
    end
  end

  defp fetch_source(resource, field, encrypted, opts) do
    case opts[:from] || encrypted.backfill_from do
      nil ->
        {:error,
         ArgumentError.exception(
           message:
             "no plaintext source for #{inspect(resource)}.#{field}. " <>
               "Pass `--from ATTR`, or declare " <>
               "`encrypt #{inspect(field)}, backfill_from: :legacy_#{field}`."
         )}

      source ->
        cond do
          source == AshVault.encrypted_field_name(field) ->
            {:error,
             ArgumentError.exception(
               message:
                 "the backfill source cannot be the ciphertext attribute #{inspect(source)}"
             )}

          is_nil(Ash.Resource.Info.attribute(resource, source)) ->
            {:error,
             ArgumentError.exception(
               message:
                 "#{inspect(resource)} has no attribute #{inspect(source)} to back-fill from. " <>
                   "The plaintext column must still exist (the \"expand\" step); it is dropped " <>
                   "only in the later \"contract\" migration."
             )}

          true ->
            {:ok, source}
        end
    end
  end

  defp fetch_primary_key(resource) do
    case Ash.Resource.Info.primary_key(resource) do
      [pk] ->
        {:ok, pk}

      other ->
        {:error,
         ArgumentError.exception(
           message:
             "backfill needs a single-attribute primary key to page with a keyset; " <>
               "#{inspect(resource)} has #{inspect(other)}."
         )}
    end
  end

  defp fetch_action(resource, opts) do
    action =
      case opts[:action] do
        nil -> Ash.Resource.Info.primary_action(resource, :update)
        name -> Ash.Resource.Info.action(resource, name)
      end

    cond do
      is_nil(action) ->
        {:error,
         ArgumentError.exception(
           message:
             "#{inspect(resource)} has no #{if opts[:action], do: inspect(opts[:action]), else: "primary"} " <>
               "update action to write the ciphertext with. Pass `--action NAME`."
         )}

      action.type != :update ->
        {:error,
         ArgumentError.exception(
           message: "#{inspect(action.name)} on #{inspect(resource)} is not an update action."
         )}

      Map.get(action, :require_atomic?) ->
        {:error,
         ArgumentError.exception(
           message:
             "update action #{inspect(action.name)} on #{inspect(resource)} is " <>
               "`require_atomic? true`, which cannot be run as a streamed bulk update. " <>
               "Pass `--action NAME` naming an update action declared `require_atomic? false`."
         )}

      true ->
        {:ok, action.name}
    end
  end

  defp resolve_vault(resource, field, tenant) do
    ash_context = %{tenant: tenant, actor: nil, source_context: %{}, phase: :write}
    vault = AshVault.Info.vault!(resource, ash_context)

    context = %AshVault.Context{resource: resource, field: field, ash_context: ash_context}
    scope = vault.__ash_vault__(:scope).resolve!(context)

    {:ok, vault, scope}
  rescue
    error in [AshVault.Errors.MissingScope] ->
      {:error,
       ArgumentError.exception(
         message:
           "cannot resolve the encryption scope for #{inspect(resource)}.#{field}: " <>
             Exception.message(error) <>
             "\nPass `--tenant TENANT`, or `--all-tenants Module.function/0`."
       )}
  end

  # -- errors and reporting ---------------------------------------------------

  defp provider_error(provider, %ProviderUnavailable{provider: nil} = error),
    do: %{error | provider: provider}

  defp provider_error(_provider, error), do: error

  defp translate_read_error(error, plan) do
    if undefined_column?(error, plan) do
      ArgumentError.exception(
        message:
          "the database has no #{plan.encrypted_field} column for #{inspect(plan.resource)}. " <>
            "Run the \"expand\" migration that adds it before back-filling " <>
            "(schema migrations need no keys; only the data backfill does)."
      )
    else
      error
    end
  end

  defp undefined_column?(error, plan) do
    message = Exception.message(error)

    String.contains?(message, "does not exist") and
      String.contains?(message, to_string(plan.encrypted_field))
  rescue
    _ -> false
  end

  defp preflight_payload(plan, total, key_status) do
    %{
      resource: plan.resource,
      field: plan.field,
      source: plan.source,
      tenant: plan.tenant,
      scope: plan.scope,
      vault: plan.vault,
      provider: plan.provider,
      key: key_status,
      total: total,
      batch_size: plan.batch_size,
      dry_run?: plan.dry_run?
    }
  end

  defp batch_payload(plan, stats, rows) do
    elapsed_ms = System.monotonic_time(:millisecond) - stats.started_at
    elapsed_s = elapsed_ms / 1000
    processed = stats.done + stats.skipped_nil_source
    remaining = max(stats.total - processed, 0)
    rate = if elapsed_s > 0, do: processed / elapsed_s, else: 0.0

    %{
      batch: stats.batches,
      rows: rows,
      done: stats.done,
      skipped_nil_source: stats.skipped_nil_source,
      remaining: remaining,
      rate: Float.round(rate, 1),
      eta_s: if(rate > 0, do: Float.round(remaining / rate, 1), else: nil),
      elapsed_s: Float.round(elapsed_s, 2),
      resume_from: stats.resume_from,
      dry_run?: plan.dry_run?
    }
  end

  defp finalize(stats) do
    elapsed_s = (System.monotonic_time(:millisecond) - stats.started_at) / 1000

    stats
    |> Map.put(:elapsed_s, Float.round(elapsed_s, 2))
    |> Map.put(:remaining, max(stats.total - stats.done - stats.skipped_nil_source, 0))
    |> Map.delete(:started_at)
  end

  defp report(%{reporter: reporter}, event) when is_function(reporter, 1), do: reporter.(event)
end
