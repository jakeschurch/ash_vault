defmodule AshVault.Test.LocalVault do
  @moduledoc """
  A vault over `AshVault.KeyProviders.Local` — key material on the filesystem.

  The acceptance suite starts the provider with a `:root` that deliberately lives
  outside anything the PostgreSQL backup covers.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
end

defmodule AshVault.Test.BaoVault do
  @moduledoc """
  A vault over `AshVault.KeyProviders.OpenBao` — key material in OpenBao transit.

  This is the convincing configuration for the §27 backup/restore acceptance test: the
  keys were never in PostgreSQL, so no PostgreSQL restore can bring them back.
  """

  use AshVault.Vault, key_provider: AshVault.KeyProviders.OpenBao
end

defmodule AshVault.Test.AcceptanceVaultResolver do
  @moduledoc """
  Resolves `AshVault.Test.AcceptanceUser`'s vault at runtime, so a single resource and a
  single table can be driven against several key providers in turn.

  The acceptance tests set `:acceptance_vault` in setup and assert, before doing anything
  else, that this resolver actually hands back the vault they think they are testing —
  otherwise a write/read vault mismatch would show up as a spurious `AuthenticationFailed`
  and could be mistaken for a passing erasure assertion.
  """

  @key :ash_vault_acceptance_vault

  @doc "Point the acceptance resource at `vault` for the current node."
  @spec put(module()) :: :ok
  def put(vault) when is_atom(vault) do
    Application.put_env(:ash_vault, @key, vault)
  end

  @doc "The vault the acceptance resource currently encrypts with."
  @spec get() :: module()
  def get, do: Application.get_env(:ash_vault, @key, AshVault.Test.Vault)

  @doc "The `fun/2` vault form `AshVault.Test.AcceptanceUser` declares."
  @spec resolve(module() | Spark.Dsl.t(), term()) :: module()
  def resolve(_resource, _context), do: get()
end

defmodule AshVault.Test.AcceptanceUser do
  @moduledoc """
  The resource the §27 backup/restore and §28 rotation acceptance tests use.

  Deliberately *not* `AshVault.Test.User`:

    * no authorizer and no field policies — a `%Ash.ForbiddenField{}` would mask a
      decryption error, and these tests exist to observe decryption errors precisely
    * a runtime-resolved vault, so the same rows-and-table plumbing runs against
      `AshVault.KeyProviders.Local` and `AshVault.KeyProviders.OpenBao`
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault &AshVault.Test.AcceptanceVaultResolver.resolve/2
    scope :tenant

    encrypt :email
    encrypt :ssn
  end

  postgres do
    table "acceptance_users"
    repo AshVault.Test.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :label, :string, public?: true
    attribute :email, :string, public?: true
    attribute :ssn, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy]

    create :create do
      primary? true
    end

    update :update do
      primary? true
      require_atomic? false
    end
  end
end

defmodule AshVault.Test.Backup do
  @moduledoc """
  Real `pg_dump` / `psql` backup and restore of the `ash_vault_test` database, for the
  §27 acceptance test.

  `pg_dump` is only available inside the PostgreSQL container here, so the dump is taken
  with `docker exec` and its stdout written to a genuine file on the host. `psql` is on
  the host PATH, so the restore runs directly. Both halves shell out to real tools — no
  savepoints, no in-transaction trickery.

  It only ever names the database from `config/test.exs`, `ash_vault_test`.
  """

  @database "ash_vault_test"
  @container "foundrybox-postgres-1"

  @doc "Whether `docker exec` into the PostgreSQL container works at all."
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

  @doc """
  `pg_dump` the test database to `path`. Returns the dump's bytes.
  """
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
          @database,
          "--no-owner",
          "--no-privileges"
        ],
        stderr_to_stdout: false
      )

    if status != 0 do
      raise "pg_dump exited #{status}: #{out}"
    end

    File.mkdir_p!(Path.dirname(path))
    File.write!(path, out)

    out
  end

  @doc """
  Drop, recreate and reload `ash_vault_test` from the dump at `path`.

  The repo is stopped first (PostgreSQL will not drop a database with live connections)
  and restarted afterwards, unlinked from the calling test process so it outlives it.
  """
  @spec restore!(Path.t()) :: :ok
  def restore!(path) do
    File.exists?(path) || raise "no dump at #{path}"

    stop_repo!()

    drop = "DROP DATABASE IF EXISTS \"" <> @database <> "\" WITH (FORCE)"
    create = "CREATE DATABASE \"" <> @database <> "\""

    psql!("postgres", ["-c", drop])
    psql!("postgres", ["-c", create])
    psql!(@database, ["-f", path])

    start_repo!()
  end

  defp psql!(database, args) do
    {out, status} =
      System.cmd(
        "psql",
        [
          # -X: ignore the developer's ~/.psqlrc. -v ON_ERROR_STOP=1: a failed statement
          # must fail the test rather than leaving a half-restored database behind.
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
          database
        ] ++ args,
        env: [{"PGPASSWORD", password()}],
        stderr_to_stdout: true
      )

    if status != 0 do
      raise "psql #{inspect(args)} against #{database} exited #{status}:\n#{out}"
    end

    :ok
  end

  defp stop_repo! do
    case Process.whereis(AshVault.Test.Repo) do
      nil ->
        :ok

      pid ->
        ref = Process.monitor(pid)
        Supervisor.stop(pid)

        receive do
          {:DOWN, ^ref, :process, ^pid, _reason} -> :ok
        after
          10_000 -> raise "AshVault.Test.Repo did not stop"
        end
    end
  end

  defp start_repo! do
    {:ok, pid} = AshVault.Test.Repo.start_link(pool_size: 10)
    # The repo was started from test_helper.exs originally; restarted here it must not
    # die with the test process that triggered the restore.
    Process.unlink(pid)
    :ok
  end

  defp repo_config, do: Application.get_env(:ash_vault, AshVault.Test.Repo, [])
  defp username, do: Keyword.get(repo_config(), :username, "postgres")
  defp password, do: Keyword.get(repo_config(), :password, "postgres")
  defp host, do: Keyword.get(repo_config(), :hostname, "localhost")
  defp port, do: repo_config() |> Keyword.get(:port, 5432) |> to_string()
end
