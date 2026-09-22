defmodule Example.Backup do
  @moduledoc """
  A real `pg_dump` / `psql` backup and restore of `ash_vault_example`.

  No savepoints, no in-transaction trickery: the dump is a file on disk produced by
  `pg_dump`, and the restore drops the database and replays that file. That is the only
  kind of backup worth demonstrating against, because a transaction rollback would
  restore the *keys* too, and the keys are the whole question.

  `pg_dump` is not on this host's PATH — it lives inside the PostgreSQL container — so
  the dump runs through `docker exec` and its stdout is written to a host file. `psql`
  *is* on the host PATH, so the restore runs directly.

  This module only ever names `ash_vault_example`.
  """

  @container System.get_env("PGCONTAINER", "foundrybox-postgres-1")

  @doc "Whether `docker exec ... pg_dump` works at all."
  @spec available?() :: boolean()
  def available? do
    case System.cmd("docker", ["exec", @container, "pg_dump", "--version"],
           stderr_to_stdout: true
         ) do
      {_out, 0} -> true
      _ -> false
    end
  rescue
    ErlangError -> false
  end

  @doc "`pg_dump` the example database to `path`, returning the dump's bytes."
  @spec dump!(Path.t()) :: binary()
  def dump!(path) do
    {out, status} =
      System.cmd(
        "docker",
        [
          "exec",
          "-e",
          "PGPASSWORD=" <> password(),
          @container,
          "pg_dump",
          "-h",
          "localhost",
          "-U",
          username(),
          "-d",
          database(),
          "--no-owner",
          "--no-privileges"
        ],
        stderr_to_stdout: false
      )

    if status != 0, do: raise("pg_dump exited #{status}: #{out}")

    File.mkdir_p!(Path.dirname(path))
    File.write!(path, out)

    out
  end

  @doc """
  Drop, recreate and reload the example database from the dump at `path`.

  The repo is terminated first — PostgreSQL will not drop a database with live
  connections — and restarted through its own supervisor afterwards.
  """
  @spec restore!(Path.t()) :: :ok
  def restore!(path) do
    File.exists?(path) || raise "no dump at #{path}"

    :ok = Supervisor.terminate_child(Example.Supervisor, Example.Repo)

    psql!("postgres", ["-c", ~s|DROP DATABASE IF EXISTS "#{database()}" WITH (FORCE)|])
    psql!("postgres", ["-c", ~s|CREATE DATABASE "#{database()}"|])
    psql!(database(), ["-f", path])

    {:ok, _pid} = Supervisor.restart_child(Example.Supervisor, Example.Repo)

    :ok
  end

  defp psql!(db, args) do
    {out, status} =
      System.cmd(
        "psql",
        [
          # -X ignores the developer's ~/.psqlrc; ON_ERROR_STOP=1 makes a failed
          # statement fail loudly rather than leaving a half-restored database.
          "-X",
          "-q",
          "-v",
          "ON_ERROR_STOP=1",
          "-h",
          host(),
          "-p",
          port(),
          "-U",
          username(),
          "-d",
          db
        ] ++ args,
        env: [{"PGPASSWORD", password()}],
        stderr_to_stdout: true
      )

    if status != 0 do
      raise "psql #{inspect(args)} against #{db} exited #{status}:\n#{out}"
    end

    :ok
  end

  defp repo_config, do: Application.get_env(:example, Example.Repo, [])
  defp database, do: Keyword.fetch!(repo_config(), :database)
  defp username, do: Keyword.get(repo_config(), :username, "postgres")
  defp password, do: Keyword.get(repo_config(), :password, "postgres")
  defp host, do: Keyword.get(repo_config(), :hostname, "localhost")
  defp port, do: repo_config() |> Keyword.get(:port, 5432) |> to_string()
end
