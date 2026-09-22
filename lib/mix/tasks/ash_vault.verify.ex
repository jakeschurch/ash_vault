defmodule Mix.Tasks.AshVault.Verify do
  @shortdoc "Decrypt a sample of encrypted rows and compare against the plaintext column"

  @moduledoc """
  Verify a backfill: decrypt a sample of rows and compare them to the plaintext column
  they were encrypted from.

  Run this between *backfill* and *cut over*. Cutting over is the irreversible step of
  the migration, so it should follow a clean verify — after it, the plaintext column is
  no longer written and the only copy of the data is the ciphertext.

  This task writes nothing and mints no key material beyond what decryption needs.

  ## Usage

      mix ash_vault.verify MyApp.Accounts.User email --tenant acme
      mix ash_vault.verify MyApp.Accounts.User email --from legacy_email --sample 0
      mix ash_vault.verify MyApp.Accounts.User email --all-tenants MyApp.Accounts.list_tenant_ids/0

  ## Options

      --from ATTR          plaintext column to compare against (default: `backfill_from`)
      --tenant TENANT      required when the key scope is `:tenant`
      --all-tenants MFA    zero-arity `Module.function/0` listing tenants
      --domain MODULE      Ash domain (inferred from `:ash_domains` when omitted)
      --batch-size N       rows per read (default 500)
      --sample N           rows to decrypt; `0` checks every row. Default: 10% of the
                           table or 1000 rows, whichever is smaller, always including the
                           first and the last row.

  ## Exit status

  Non-zero on the first tenant with any mismatch — a row whose ciphertext is NULL, whose
  plaintext differs, or which fails to decrypt at all. The summary names the offending
  primary keys.

      ash_vault.verify=result resource=MyApp.Accounts.User field=email rows=2000 checked=200 mismatches=0
      Verified 200 of 2000 row(s) of MyApp.Accounts.User.email: no mismatches.
  """

  use Mix.Task

  alias AshVault.Mix.Shared

  @switches [
    from: :string,
    tenant: :string,
    all_tenants: :string,
    domain: :string,
    batch_size: :integer,
    sample: :integer
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
        _ -> Shared.abort!("usage: mix ash_vault.verify RESOURCE FIELD [options]")
      end

    opts
    |> Shared.tenants!()
    |> Enum.each(&verify_tenant(resource, field, &1, opts))
  end

  defp verify_tenant(resource, field, tenant, opts) do
    engine_opts = [
      from: opts[:from] && String.to_atom(opts[:from]),
      tenant: tenant,
      domain: Shared.domain(opts),
      batch_size: opts[:batch_size],
      sample: opts[:sample],
      verify?: true,
      reporter: &report(resource, field, tenant, &1)
    ]

    case AshVault.Backfill.run(resource, field, engine_opts) do
      {:ok, stats} ->
        Shared.say(
          "Verified #{stats.checked} of #{stats.total} row(s) of " <>
            "#{inspect(resource)}.#{field}: no mismatches."
        )

      {:error, error} ->
        Shared.abort!(Exception.message(error))

      {:error, error, _stats} ->
        Shared.abort!(Exception.message(error))
    end
  end

  defp report(resource, field, tenant, {:verify_done, payload}) do
    Shared.kv(
      "ash_vault.verify": "result",
      resource: resource,
      field: field,
      tenant: tenant,
      rows: payload.total,
      checked: payload.checked,
      mismatches: length(payload.mismatches)
    )
  end

  defp report(_resource, _field, _tenant, _event), do: :ok
end
