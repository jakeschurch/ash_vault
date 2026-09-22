defmodule AshVault.Test.Db do
  @moduledoc """
  Creates and shapes the `ash_vault_test` database for the `:postgres`-tagged suites.

  The schema is applied as plain SQL rather than through generated migrations: the
  extension layer's tables are small and fixed, and this keeps the harness to one file
  with no migration directory to drift.

  It only ever touches the database named in `config/test.exs` — `ash_vault_test`.
  """

  @database "ash_vault_test"

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
    CREATE TABLE IF NOT EXISTS contacts (
      id uuid PRIMARY KEY,
      org_id uuid NOT NULL,
      encrypted_phone bytea
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

    case Postgrex.query(conn, ~s(CREATE DATABASE "#{@database}"), []) do
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
    AshVault.Test.Repo.query!("TRUNCATE users, contacts, organizations")
    :ok
  end
end
