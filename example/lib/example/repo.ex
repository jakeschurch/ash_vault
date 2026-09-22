defmodule Example.Repo do
  @moduledoc """
  The example's PostgreSQL repo. It points at `ash_vault_example` and nothing else.
  """

  use AshPostgres.Repo, otp_app: :example

  @impl AshPostgres.Repo
  def installed_extensions, do: ["ash-functions"]

  @impl AshPostgres.Repo
  def min_pg_version, do: %Version{major: 16, minor: 0, patch: 0}
end
