defmodule Mix.Tasks.AshVault.KeyInfo do
  @shortdoc "Show a scope's key name, current version, timestamps and tombstone state"

  @moduledoc """
  Report the key state of an AshVault scope: which provider serves it, what it is called
  there, its current version, when that version was minted, which historical versions are
  still fetchable, and whether the scope has been crypto-erased.

  This task is read-only in the strongest sense: it **never mints key material**.
  `AshVault.KeyProvider.current_key/1` mints version 1 on first use, so an unused scope is
  detected with `get_key/2` first and reported as `not_minted` without creating anything.

  ## Usage

      mix ash_vault.key_info MyApp.Accounts.User --tenant acme
      mix ash_vault.key_info MyApp.Accounts.User --all-tenants MyApp.Accounts.list_tenant_ids/0
      mix ash_vault.key_info MyApp.Notes            # a `scope :global` resource

  ## Options

      --tenant TENANT      required when the key scope is `:tenant`
      --all-tenants MFA    zero-arity `Module.function/0` listing tenants
      --domain MODULE      Ash domain (inferred from `:ash_domains` when omitted)

  ## Output

      ash_vault.key_info=scope resource=MyApp.Accounts.User tenant=acme scope=acme \\
        vault=MyApp.Vault provider=AshVault.KeyProviders.OpenBao key_name=ashvault-acme \\
        status=active version=3 created_at=2026-02-01T10:12:00Z versions=1,2,3
      MyApp.Vault: scope acme is active at key version 3 (3 version(s) retained).

  `status` is one of `active`, `not_minted` or `destroyed`. A destroyed scope exits 0 —
  a tombstone is a legitimate answer, not a failure.
  """

  use Mix.Task

  alias AshVault.Mix.Shared

  @switches [tenant: :string, all_tenants: :string, domain: :string]

  @requirements ["app.start"]

  @doc false
  @impl Mix.Task
  def run(argv) do
    Shared.start_app!(argv)

    {opts, args} = OptionParser.parse!(argv, strict: @switches)

    resource =
      case args do
        [resource] -> Shared.resource!(resource)
        _ -> Shared.abort!("usage: mix ash_vault.key_info RESOURCE [options]")
      end

    opts
    |> Shared.tenants!()
    |> Enum.each(&report_tenant(resource, &1))
  end

  defp report_tenant(resource, tenant) do
    %{vault: vault, scope: scope, provider: provider} = Shared.resolve!(resource, tenant)

    base = [
      "ash_vault.key_info": "scope",
      resource: resource,
      tenant: tenant,
      scope: scope,
      vault: vault,
      provider: provider,
      key_name: key_name(provider, scope)
    ]

    case Shared.key_state(provider, scope) do
      :destroyed ->
        Shared.kv(base ++ [status: "destroyed"])

        Shared.say(
          "#{inspect(vault)}: scope #{Shared.format(scope)} is DESTROYED — every value encrypted under it is permanently unrecoverable."
        )

      :not_minted ->
        Shared.kv(base ++ [status: "not_minted"])

        Shared.say(
          "#{inspect(vault)}: scope #{Shared.format(scope)} has no key yet; one is minted on first write."
        )

      {:active, info} ->
        Shared.kv(
          base ++
            [
              status: "active",
              version: info.version,
              created_at: info.created_at,
              versions: info.versions
            ]
        )

        Shared.say(
          "#{inspect(vault)}: scope #{Shared.format(scope)} is active at key version " <>
            "#{info.version} (#{length(info.versions)} version(s) retained)."
        )

      {:error, reason} ->
        Shared.abort!(
          Exception.message(
            AshVault.Errors.ProviderUnavailable.exception(provider: provider, reason: reason)
          )
        )
    end
  end

  defp key_name(provider, scope) do
    if function_exported?(provider, :key_name, 1), do: provider.key_name(scope)
  end
end
