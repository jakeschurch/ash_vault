defmodule Mix.Tasks.AshVault.Openbao.InitRetirement do
  @shortdoc "Import KV tombstones and activate the OpenBao retirement plugin"
  @moduledoc """
  Activate a retirement-plugin mount after importing every existing KV tombstone.

      mix ash_vault.openbao.init_retirement AshVault.KeyProviders.OpenBao
      mix ash_vault.openbao.init_retirement AshVault.KeyProviders.OpenBaoTransit

  Run with writers stopped, after installing the plugin at the configured Transit
  mount. Uses the named provider's configuration and an operator token with `sudo`
  on `<transit_mount>/ashvault/initialize`, read access to `sys/mounts` to verify KV-v2,
  plus read/list access to KV tombstones and
  update access to `<transit_mount>/ashvault/retire/*`. This task loads application
  configuration without starting the application, so an uninitialized plugin cannot
  deadlock application startup. The HTTP dependencies are started explicitly.

  Import and activation are idempotent. An unreadable tombstone, invalid listing or
  failed retirement stops activation. Never initialize a migrated mount directly:
  importing its previous tombstones is required to preserve erasure.
  """
  use Mix.Task

  alias AshVault.KeyProviders.OpenBao.Transport

  @impl Mix.Task
  def run(argv) do
    Mix.Task.run("app.config")
    {:ok, _} = Application.ensure_all_started(:req)
    {:ok, _} = Application.ensure_all_started(:ash_vault)

    provider =
      case argv do
        ["AshVault.KeyProviders.OpenBao"] -> AshVault.KeyProviders.OpenBao
        ["AshVault.KeyProviders.OpenBaoTransit"] -> AshVault.KeyProviders.OpenBaoTransit
        _ -> Mix.raise("usage: mix ash_vault.openbao.init_retirement PROVIDER")
      end

    case Transport.initialize_retirement(provider) do
      :ok -> Mix.shell().info("OpenBao server retirement initialized; KV tombstones imported.")
      {:error, error} -> Mix.raise(Exception.message(error))
    end
  end
end
