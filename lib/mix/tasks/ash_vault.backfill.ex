defmodule Mix.Tasks.AshVault.Backfill do
  @shortdoc "Encrypt an existing plaintext column, online, in committed batches"

  @moduledoc """
  Encrypt an existing plaintext column into its `encrypted_<field>` column, online.

  This is step 3 of the *expand / backfill / cut over / contract* migration:

    1. **Expand** — an ordinary Ash/Ecto migration adds `encrypted_email`. Schema
       migrations never need keys.
    2. **Deploy** the transitional resource: `encrypt :email, backfill_from: :legacy_email`
       (or pass `--from` here). The plaintext column is still there.
    3. **Backfill** — this task. It needs the app runtime and a reachable key provider.
    4. **Verify** — `mix ash_vault.verify`, or `--verify` here.
    5. **Cut over** — point reads and writes at the encrypted field. *This is the
       irreversible step*; do it only after a clean verify.
    6. **Contract** — drop the plaintext column in a later migration.

  There is no decrypt-back mode. Until step 6 the plaintext column is still there, which
  is the rollback.

  ## Usage

      mix ash_vault.backfill MyApp.Accounts.User email --tenant acme
      mix ash_vault.backfill MyApp.Accounts.User email --from legacy_email --batch-size 1000
      mix ash_vault.backfill MyApp.Accounts.User email --all-tenants MyApp.Accounts.list_tenant_ids/0
      mix ash_vault.backfill MyApp.Accounts.User email --tenant acme --dry-run
      mix ash_vault.backfill MyApp.Accounts.User email --tenant acme --verify
      mix ash_vault.backfill MyApp.Accounts.User email --tenant acme --lookup

  ## `--lookup`

  Populates the deterministic `<field>_lookup` column of a `searchable?: true` field for
  rows that already hold ciphertext — after adding `searchable?: true` to an existing
  encrypted field, or after deliberately re-keying the provider's lookup secret.

  It reads, decrypts, normalizes, hashes, and writes **only** the token column. The
  ciphertext is never rewritten: a fresh nonce would churn a column this mode has no
  business touching.

  > #### It cannot repair a changed `normalize:` {: .warning}
  >
  > AshVault encrypts the *normalized* value, so the ciphertext and the token must agree
  > about what the row holds. Changing `normalize:` on a populated column makes them
  > disagree, and hashing the newly normalized value would leave those rows findable under
  > one spelling and readable as another. The task detects that and aborts, naming the row,
  > rather than writing the inconsistency. Reconciling the two requires re-encrypting, and
  > by this point there is no plaintext column left to re-encrypt from.

  Rotating a lookup key is this task, not `mix ash_vault.rotate`. `rotate` mints a new
  data key version and deliberately leaves every token alone — if it moved them, every
  existing row would silently stop being findable.

  > #### It is NOT part of an ordinary backfill {: .info}
  >
  > Back-filling a `searchable?: true` field writes the ciphertext **and** its token in
  > the same batch, through `AshVault.write_attributes/4` — the same function an ordinary
  > create or update calls. `--lookup` is for the two cases where the ciphertext is
  > already there and only the token is missing: retro-fitting `searchable?: true` onto a
  > populated column, and rotating the provider's lookup secret.

  Like the ciphertext backfill it is resumable and idempotent with no state file: it
  selects only rows whose token `IS NULL` and whose ciphertext `IS NOT NULL`, so a
  second run is a no-op. It writes, so it cannot be combined with `--verify`, which
  writes nothing — and does not need to be: plain `--verify` checks the token column for
  you, by recomputing it from the decrypted value.

  ## Options

      --from ATTR          plaintext source attribute (default: the field's `backfill_from`)
      --batch-size N       rows per committed transaction (default 500)
      --tenant TENANT      required when the key scope is `:tenant`
      --all-tenants MFA    zero-arity `Module.function/0` listing tenants
      --domain MODULE      Ash domain (inferred from `:ash_domains` when omitted)
      --action NAME        update action to write with (default: the primary update
                           action; it must be `require_atomic? false`)
      --lookup             populate `<field>_lookup` tokens for rows that already have
                           ciphertext; reads and decrypts, writes only the token column
      --verify             decrypt a sample and compare to the plaintext column — and,
                           for a `searchable?` field, recompute and compare its
                           `<field>_lookup` token; write nothing
      --dry-run            report what would be done; write nothing
      --resume-from ID     start after this primary key (one tenant only; it cannot be
                           combined with `--all-tenants`)
      --sample N           rows to check in `--verify` mode (`0` checks every row)
      --yes                skip the confirmation prompt

  ## Guarantees

    * Rows are ordered by primary key and paged with a keyset (`pk > last_seen`), never
      `OFFSET`.
    * Only rows whose encrypted column `IS NULL` are selected, so a re-run is a no-op and
      an interrupted run resumes with no state file.
    * Each batch is its own transaction. The table is never wrapped in one.
    * The key provider is checked **before** the first batch; an unreachable provider
      fails with `ProviderUnavailable` rather than half a written table. If it goes away
      mid-run, the task stops at the batch boundary and prints the exact resume command.
    * Only the encrypted column is written — plus the `<field>_lookup` token when the
      field is `searchable?: true`, because a row holding one without the other is a row
      that decrypts correctly and cannot be found.

  ## Output

  One `key=value` line per batch, then a human summary:

      ash_vault.backfill resource=MyApp.Accounts.User field=email source=legacy_email ...
      batch=1 rows=500 done=500 remaining=1500 rate=812.3 eta_s=1.8 elapsed_s=0.62
      Backfilled 2000 row(s) of MyApp.Accounts.User.email in 4 batch(es) (2.4s).
  """

  use Mix.Task

  alias AshVault.Mix.Shared

  @switches [
    lookup: :boolean,
    from: :string,
    batch_size: :integer,
    tenant: :string,
    all_tenants: :string,
    domain: :string,
    action: :string,
    verify: :boolean,
    dry_run: :boolean,
    resume_from: :string,
    sample: :integer,
    yes: :boolean
  ]

  @requirements ["app.start"]

  @doc false
  @impl Mix.Task
  def run(argv) do
    Shared.start_app!(argv)

    {opts, args} = OptionParser.parse!(argv, strict: @switches)

    {resource, field} =
      case args do
        [resource, field] -> {Shared.resource!(resource), String.to_atom(field)}
        _ -> Shared.abort!("usage: mix ash_vault.backfill RESOURCE FIELD [options]")
      end

    if opts[:all_tenants] && opts[:resume_from] do
      Shared.abort!("""
      `--all-tenants` and `--resume-from` cannot be combined.

      `--resume-from` is a keyset offset into ONE tenant's rows. Applied across tenants it
      would be a different, meaningless row in each of the others: every tenant would skip
      the rows whose primary key sorts below that id and report `done == total,
      remaining: 0`, because the pending count excludes the skipped prefix too. The run
      would look complete with rows left unencrypted.

      Resume the one tenant that failed:

          mix ash_vault.backfill RESOURCE FIELD --tenant TENANT --resume-from #{opts[:resume_from]}

      then re-run `--all-tenants` with no `--resume-from`. The backfill is idempotent —
      it selects only rows whose target column is still NULL — so the tenants that already
      finished cost one scan and write nothing.
      """)
    end

    tenants = Shared.tenants!(opts)

    if !opts[:verify] and !opts[:dry_run] do
      what =
        if opts[:lookup] do
          "Populate #{inspect(resource)}.#{AshVault.lookup_field_name(field)} tokens"
        else
          "Encrypt #{inspect(resource)}.#{field}"
        end

      Shared.confirm!("#{what} for #{length(tenants)} tenant(s)?", opts)
    end

    Enum.each(tenants, &run_tenant(resource, field, &1, opts))
  end

  defp run_tenant(resource, field, tenant, opts) do
    engine_opts = [
      lookup?: !!opts[:lookup],
      from: opts[:from] && String.to_atom(opts[:from]),
      action: opts[:action] && String.to_atom(opts[:action]),
      tenant: tenant,
      domain: Shared.domain(opts),
      batch_size: opts[:batch_size],
      resume_from: opts[:resume_from],
      sample: opts[:sample],
      dry_run?: !!opts[:dry_run],
      verify?: !!opts[:verify],
      reporter: &report/1
    ]

    case AshVault.Backfill.run(resource, field, engine_opts) do
      {:ok, %{verify?: true} = stats} ->
        Shared.say(
          "Verified #{stats.checked} of #{stats.total} row(s) of " <>
            "#{inspect(resource)}.#{field}: no mismatches."
        )

      {:ok, stats} ->
        Shared.say(summary(resource, field, tenant, stats))

      {:error, error} ->
        Shared.abort!(Exception.message(error))

      {:error, error, %{verify?: true}} ->
        Shared.abort!(failure_message(tenant, error))

      {:error, error, stats} ->
        Shared.say(resume_hint(resource, field, tenant, stats, opts))
        Shared.abort!(failure_message(tenant, error))
    end
  end

  defp summary(resource, field, tenant, stats) do
    prefix = if stats.dry_run?, do: "Dry run: would back-fill", else: "Backfilled"

    "#{prefix} #{stats.done} row(s) of #{inspect(resource)}.#{field}" <>
      tenant_suffix(tenant) <>
      " in #{stats.batches} batch(es) (#{stats.elapsed_s}s)" <>
      skipped_suffix(stats) <> "."
  end

  defp tenant_suffix(nil), do: ""
  defp tenant_suffix(tenant), do: " for tenant #{Shared.format(tenant)}"

  defp skipped_suffix(%{skipped_nil_source: 0}), do: ""

  defp skipped_suffix(%{skipped_nil_source: n}),
    do: ", #{n} row(s) skipped (nil source, `encrypt_nil?: false`)"

  defp failure_message(nil, error), do: Exception.message(error)

  defp failure_message(tenant, error),
    do: "tenant #{Shared.format(tenant)}: " <> Exception.message(error)

  defp resume_hint(resource, field, tenant, stats, opts) do
    """

    Stopped at a batch boundary. #{stats.done} row(s) are committed; the rest are untouched.
    Resume with:

        mix ash_vault.backfill #{inspect(resource)} #{field}#{resume_args(tenant, stats, opts)}
    """
  end

  defp resume_args(tenant, stats, opts) do
    [
      if(opts[:lookup], do: [" ", "--lookup"], else: []),
      switch("--from", opts[:from]),
      switch("--action", opts[:action]),
      switch("--domain", opts[:domain]),
      switch("--batch-size", opts[:batch_size]),
      switch("--tenant", tenant),
      switch("--resume-from", stats.resume_from)
    ]
    |> IO.iodata_to_binary()
  end

  defp switch(_name, nil), do: []
  defp switch(name, value), do: [" ", name, " ", Shared.format(value)]

  defp report({:preflight, payload}) do
    Shared.kv(
      "ash_vault.backfill": "start",
      resource: payload.resource,
      field: payload.field,
      source: payload.source,
      target: payload.target,
      lookup: payload.lookup?,
      tenant: payload.tenant,
      scope: payload.scope,
      vault: payload.vault,
      provider: payload.provider,
      key: key_status(payload.key),
      rows: payload.total,
      batch_size: payload.batch_size,
      dry_run: payload.dry_run?
    )
  end

  defp report({:batch, payload}) do
    Shared.kv(
      batch: payload.batch,
      rows: payload.rows,
      done: payload.done,
      skipped: payload.skipped_nil_source,
      remaining: payload.remaining,
      rate: payload.rate,
      eta_s: payload.eta_s,
      elapsed_s: payload.elapsed_s,
      last_pk: payload.resume_from
    )
  end

  defp report({:done, payload}) do
    Shared.kv(
      "ash_vault.backfill": "done",
      rows: payload.total,
      done: payload.done,
      skipped: payload.skipped_nil_source,
      batches: payload.batches,
      elapsed_s: payload.elapsed_s
    )
  end

  defp report({:verify_done, payload}) do
    Shared.kv(
      "ash_vault.backfill": "verify",
      rows: payload.total,
      checked: payload.checked,
      mismatches: length(payload.mismatches)
    )
  end

  defp report(_event), do: :ok

  defp key_status({:current, version}), do: "v#{version}"
  defp key_status(other), do: other
end
