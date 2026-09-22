defmodule AshVault.Test.Db do
  @moduledoc """
  Creates and shapes the `ash_vault_test` database for the `:postgres`-tagged suites.

  The schema is applied as plain SQL rather than through generated migrations: the
  extension layer's tables are small and fixed, and this keeps the harness to one file
  with no migration directory to drift.

  It only ever touches the database named in `config/test.exs` — `ash_vault_test`, or
  whatever `ASHVAULT_TEST_DB` overrides it to. Never `foundry_dev`.
  """

  # Read from the repo config rather than hardcoded, so `ASHVAULT_TEST_DB` moves the
  # whole harness — creation included — to another database in one place.
  defp database do
    name = Application.get_env(:ash_vault, AshVault.Test.Repo)[:database]

    # This harness TRUNCATEs — and, in `AshVault.Test.Backup`, DROPs — whatever this
    # returns. The prefix check is the only thing standing between a mistyped
    # `ASHVAULT_TEST_DB` and somebody's development database. It must never be relaxed.
    unless is_binary(name) and String.starts_with?(name, "ash_vault_test") do
      raise "refusing to operate on #{inspect(name)}: the AshVault test harness only ever " <>
              "touches a database whose name starts with \"ash_vault_test\""
    end

    name
  end

  @statements [
    """
    CREATE TABLE IF NOT EXISTS organizations (
      id uuid PRIMARY KEY,
      name text
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      org_id uuid NOT NULL,
      name text,
      encrypted_email bytea,
      encrypted_ssn bytea,
      encrypted_profile bytea,
      encrypted_tags bytea,
      encrypted_contacts bytea
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS legacy_users (
      id uuid PRIMARY KEY,
      org_id uuid NOT NULL,
      legacy_email text,
      encrypted_email bytea
    )
    """,
    """
    ALTER TABLE legacy_users
      ADD COLUMN IF NOT EXISTS legacy_ssn text,
      ADD COLUMN IF NOT EXISTS encrypted_ssn bytea
    """,
    """
    CREATE TABLE IF NOT EXISTS contacts (
      id uuid PRIMARY KEY,
      org_id uuid NOT NULL,
      encrypted_phone bytea
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS search_users (
      id uuid PRIMARY KEY,
      org_id uuid NOT NULL,
      encrypted_email bytea,
      email_lookup bytea
    )
    """,
    # A plaintext column beside the token, so an upsert's UPDATE half has something
    # visibly non-key to change. Without it "the upsert updated the row" and "the upsert
    # did nothing" look identical, which is exactly the failure mode
    # `upsert_fields: [:email]` produces.
    """
    ALTER TABLE search_users ADD COLUMN IF NOT EXISTS name text
    """,
    # `unique?: true` on a searchable field. The tenant column is part of the index
    # because Ash puts it there itself for an attribute-multitenant resource whenever the
    # identity is not `all_tenants?`
    # (deps/ash_postgres/lib/migration_generator/operation.ex:142-148) — the identity
    # AshVault generates lists only `[:email_lookup]`.
    #
    # Postgres already ignores NULLs in a unique index, which is the same thing
    # `nils_distinct?: true` means to Ash: any number of rows may hold a nil email.
    """
    CREATE UNIQUE INDEX IF NOT EXISTS search_users_email_lookup_unique_index
      ON search_users (org_id, email_lookup)
    """,
    # A searchable field WITHOUT `unique?`, so duplicates are possible — the shape every
    # table has before someone adds the constraint, and the only shape where the
    # GROUP BY dedupe recipe has anything to find.
    """
    CREATE TABLE IF NOT EXISTS dedupe_users (
      id uuid PRIMARY KEY,
      org_id uuid NOT NULL,
      name text,
      encrypted_email bytea,
      email_lookup bytea
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS dedupe_users_email_lookup_index
      ON dedupe_users (org_id, email_lookup)
    """,
    """
    CREATE TABLE IF NOT EXISTS acceptance_users (
      id uuid PRIMARY KEY,
      org_id uuid NOT NULL,
      label text,
      encrypted_email bytea,
      encrypted_ssn bytea
    )
    """
  ]

  @doc """
  Create the database (if needed), start the repo, and apply the schema.
  """
  @spec setup!() :: :ok
  def setup! do
    create_database!()

    {:ok, _pid} = AshVault.Test.Repo.start_link(pool_size: 10)

    Enum.each(@statements, &AshVault.Test.Repo.query!/1)

    :ok
  end

  defp create_database! do
    config =
      :ash_vault
      |> Application.get_env(AshVault.Test.Repo)
      |> Keyword.drop([:pool, :pool_size])
      |> Keyword.put(:database, "postgres")

    {:ok, conn} = Postgrex.start_link(config)

    case Postgrex.query(conn, ~s(CREATE DATABASE "#{database()}"), []) do
      {:ok, _} -> :ok
      # 42P04 = duplicate_database
      {:error, %Postgrex.Error{postgres: %{code: :duplicate_database}}} -> :ok
      {:error, error} -> raise error
    end

    GenServer.stop(conn)
  end

  @doc """
  Truncate every test table. Cheaper and simpler than the Ecto sandbox here, because the
  key provider's state is process-global anyway.
  """
  @spec reset!() :: :ok
  def reset! do
    _ = database()

    AshVault.Test.Repo.query!(
      "TRUNCATE users, contacts, legacy_users, organizations, acceptance_users, search_users, dedupe_users"
    )

    :ok
  end
end
