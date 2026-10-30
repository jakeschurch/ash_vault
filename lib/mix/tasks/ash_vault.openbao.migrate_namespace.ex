defmodule Mix.Tasks.AshVault.Openbao.MigrateNamespace do
  @shortdoc "Migrate an ambiguous binary OpenBao scope without exporting keys"
  @moduledoc """
  Move a binary scope whose base64url representation starts with `nx_` to the
  disjoint exporting-provider namespace, preserving every key version and tombstone.

      mix ash_vault.openbao.migrate_namespace BASE64URL_SCOPE
      mix ash_vault.openbao.migrate_namespace BASE64URL_SCOPE --rollback

  Uses `AshVault.KeyProviders.OpenBao` configuration. Stop all writers and drain
  requests during migration or rollback. Requires the updated AshVault server plugin,
  an operator token with `sudo` and `update` on `<mount>/ashvault/namespace/*`,
  `read` on `sys/mounts`, and KV read/write access to tombstones and namespaces.
  The application and its older versions must remain stopped until migration finishes.
  Ordinary text tenant identifiers need no migration. Fresh scopes in the reserved
  binary range use this same task to establish their namespace explicitly.

  The task never receives key bytes. Server changes are transactional and retries are
  idempotent. KV readiness is recorded last, so interrupted migration fails closed.
  Rollback refuses erased scopes or an occupied legacy destination; it restores the
  original names and disables the new namespace. Keep writers stopped on any failure
  and retry the same direction. Never restore a key backup to undo a retirement.
  """
  use Mix.Task

  @impl Mix.Task
  def run(argv) do
    Mix.Task.run("app.config")
    {:ok, _} = Application.ensure_all_started(:req)
    {:ok, _} = Application.ensure_all_started(:ash_vault)
    {opts, args} = OptionParser.parse!(argv, strict: [rollback: :boolean])

    scope =
      case args do
        [encoded] ->
          case Base.url_decode64(encoded, padding: false) do
            {:ok, scope} ->
              if Base.url_encode64(scope, padding: false) != encoded,
                do: Mix.raise("scope must be canonical base64url")

              scope

            :error ->
              Mix.raise("scope must be canonical base64url")
          end

        _ ->
          Mix.raise("usage: mix ash_vault.openbao.migrate_namespace BASE64URL_SCOPE [--rollback]")
      end

    case AshVault.KeyProviders.OpenBao.Transport.migrate_binary_namespace(
           AshVault.KeyProviders.OpenBao,
           scope,
           Keyword.get(opts, :rollback, false)
         ) do
      :ok -> Mix.shell().info("OpenBao scope namespace migration completed.")
      {:error, error} -> Mix.raise(Exception.message(error))
    end
  end
end
