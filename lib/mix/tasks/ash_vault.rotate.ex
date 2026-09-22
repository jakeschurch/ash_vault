defmodule Mix.Tasks.AshVault.Rotate do
  @shortdoc "Rotate a scope's encryption key, minting a new version"

  @moduledoc """
  Mint a new key version for a scope.

  Rotation is **not** destructive: every existing value keeps decrypting with the key
  version recorded in its envelope, and only new writes use the new version. Nothing
  needs re-encrypting; if you want old rows on the new key, re-save them.

  ## Usage

      mix ash_vault.rotate MyApp.Accounts.User --tenant acme
      mix ash_vault.rotate MyApp.Accounts.User --all-tenants MyApp.Accounts.list_tenant_ids/0 --yes
      mix ash_vault.rotate MyApp.Notes                 # a `scope :global` resource

  ## Options

      --tenant TENANT      required when the key scope is `:tenant`
      --all-tenants MFA    zero-arity `Module.function/0` listing tenants
      --domain MODULE      Ash domain (inferred from `:ash_domains` when omitted)
      --yes                skip the confirmation prompt

  ## Output

      ash_vault.rotate=done resource=MyApp.Accounts.User tenant=acme scope=acme \\
        vault=MyApp.Vault provider=MyApp.KeyProvider old_version=2 new_version=3
      Rotated MyApp.Vault scope acme: key version 2 -> 3.

  Rotating a destroyed scope is an error and exits non-zero: the tombstone is permanent
  and re-minting would turn crypto-erasure into silent data loss.
  """

  use Mix.Task

  alias AshVault.Mix.Shared

  @switches [tenant: :string, all_tenants: :string, domain: :string, yes: :boolean]

  @requirements ["app.start"]

  @doc false
  @impl Mix.Task
  def run(argv) do
    Shared.start_app!(argv)

    {opts, args} = OptionParser.parse!(argv, strict: @switches)

    resource =
      case args do
        [resource] -> Shared.resource!(resource)
        _ -> Shared.abort!("usage: mix ash_vault.rotate RESOURCE [options]")
      end

    tenants = Shared.tenants!(opts)

    Shared.confirm!(
      "Rotate the AshVault key for #{length(tenants)} scope(s) of #{inspect(resource)}?",
      opts
    )

    Enum.each(tenants, &rotate_tenant(resource, &1))
  end

  defp rotate_tenant(resource, tenant) do
    %{vault: vault, scope: scope, provider: provider} = Shared.resolve!(resource, tenant)

    old_version =
      case Shared.key_state(provider, scope) do
        {:active, %{version: version}} ->
          version

        :not_minted ->
          nil

        :destroyed ->
          Shared.abort!(
            "scope #{Shared.format(scope)} has been destroyed; its keys can never be re-minted."
          )

        {:error, reason} ->
          Shared.abort!(
            Exception.message(
              AshVault.Errors.ProviderUnavailable.exception(provider: provider, reason: reason)
            )
          )
      end

    case rotate(vault, scope) do
      {:ok, new_version} ->
        Shared.kv(
          "ash_vault.rotate": "done",
          resource: resource,
          tenant: tenant,
          scope: scope,
          vault: vault,
          provider: provider,
          old_version: old_version,
          new_version: new_version
        )

        Shared.say(
          "Rotated #{inspect(vault)} scope #{Shared.format(scope)}: key version " <>
            "#{Shared.format(old_version)} -> #{new_version}."
        )

      {:error, error} ->
        Shared.abort!(Exception.message(error))
    end
  end

  defp rotate(vault, scope) do
    AshVault.rotate_key!(vault, scope)
  rescue
    error -> {:error, error}
  end
end
