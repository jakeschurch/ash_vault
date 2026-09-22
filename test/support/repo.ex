defmodule AshVault.Test.Repo do
  @moduledoc """
  The PostgreSQL repo for AshVault's `:postgres`-tagged tests.

  It points at the `ash_vault_test` database and nothing else — see `config/test.exs`.
  """

  use AshPostgres.Repo, otp_app: :ash_vault

  @impl AshPostgres.Repo
  def installed_extensions, do: ["ash-functions"]

  @impl AshPostgres.Repo
  def min_pg_version, do: %Version{major: 16, minor: 0, patch: 0}
end
