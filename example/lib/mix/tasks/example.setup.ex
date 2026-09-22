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

    2. The key provider's operator setup step runs — `Example.Vault.current().setup()`,
       one line for either provider, because the vault knows which one it has.

       With `ASHVAULT_PROVIDER=local` that initialises the key root. The provider
       refuses to start on a directory it did not see initialised — that is what
       stops an unmounted key volume from looking like a pristine, never-used key
       store, which would silently mint fresh keys and orphan every existing row.

       With OpenBao it creates the KV-v2 mount that holds tombstones. The provider
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
    # The OpenBao provider speaks HTTP through `req`, whose Finch pool has to be running.
    # A Mix task only configures the application; it does not start it. Forgetting this
    # is no longer mistakable for an outage — AshVault reports `{:not_started, :req}`
    # and says what to do — but there is nothing to report if we just start it.
    {:ok, _apps} = Application.ensure_all_started(:req)

    # One line, whichever provider is configured: `setup/0` initialises the Local key
    # root, mounts OpenBao's KV-v2 tombstone engine, and is `:ok` for a provider that
    # needs neither.
    case Example.Vault.current().setup() do
      :ok ->
        Mix.shell().info("key provider ready: #{inspect(Example.Vault.key_provider())}")

      {:error, error} ->
        Mix.raise("""
        could not prepare #{inspect(Example.Vault.key_provider())}:

        #{Exception.message(error)}
        """)
    end
  end

  defp database, do: Application.get_env(:example, Example.Repo)[:database]
end
