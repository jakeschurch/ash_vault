defmodule Mix.Tasks.Example.Setup do
  @shortdoc "Create the example database, migrate it, and prepare the key provider."

  @moduledoc """
  One-shot setup for the AshVault example.

      mix example.setup            # create + migrate, idempotent
      mix example.setup --reset    # drop the database first (a clean run)

  Three things happen here, and the third is the one people forget:

    1. `ash_vault_example` is created and migrated. The migration is worth reading:
       there is no `email` column and no `phone` column, only `encrypted_email` and
       `encrypted_phone` `bytea`. AshVault removes the plaintext attribute from the
       resource, so no data layer can write a plaintext column.

    2. With `ASHVAULT_PROVIDER=local`, the key root is initialised. The provider
       refuses to start on a directory it did not see initialised — that is what
       stops an unmounted key volume from looking like a pristine, never-used key
       store, which would silently mint fresh keys and orphan every existing row.

    3. With OpenBao, the KV-v2 mount that holds tombstones is created. The provider
       deliberately never creates it on a read: a missing mount answers 404, exactly
       like "no tombstone here", so auto-provisioning it on read would be fail-open —
       a freshly created empty mount makes every erased tenant look intact again.
  """

  use Mix.Task

  @requirements ["app.config"]

  @impl Mix.Task
  def run(args) do
    reset? = "--reset" in args

    if reset? do
      Mix.shell().info("dropping #{database()} ...")
      Mix.Task.run("ash_postgres.drop", ["--quiet"])
    end

    Mix.Task.run("ash_postgres.create", ["--quiet"])
    Mix.Task.run("ash_postgres.migrate", [])

    prepare_key_provider!()

    Mix.shell().info("""

    setup complete.
      database     #{database()}
      key provider #{inspect(Example.Vault.key_provider())}

    Now run: mix example.demo
    """)
  end

  defp prepare_key_provider! do
    case Example.Vault.key_provider() do
      AshVault.KeyProviders.Local ->
        root = Keyword.fetch!(Application.get_env(:ash_vault, AshVault.KeyProviders.Local), :root)
        AshVault.KeyProviders.Local.init_root!(root)
        Mix.shell().info("initialised Local key root at #{root} (mode 0700)")

      AshVault.KeyProviders.OpenBao ->
        # The provider speaks HTTP through `req`, whose Finch pool has to be running.
        # A Mix task only configures the app; it does not start it.
        {:ok, _apps} = Application.ensure_all_started(:req)

        case AshVault.KeyProviders.OpenBao.setup() do
          :ok ->
            Mix.shell().info("OpenBao KV-v2 tombstone mount is ready")

          other ->
            Mix.raise("""
            could not prepare OpenBao: #{inspect(other)}

            Is the dev server up?
              curl -s http://127.0.0.1:8200/v1/sys/health
            """)
        end

      other ->
        Mix.shell().info("no setup needed for #{inspect(other)}")
    end
  end

  defp database, do: Application.get_env(:example, Example.Repo)[:database]
end
