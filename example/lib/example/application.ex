defmodule Example.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # The vault answers for its own provider. OpenBao is stateless HTTP and contributes
    # nothing here; Local is a GenServer serialising every mutation of the key directory
    # and contributes itself. Neither is a `case` this application writes.
    children = [Example.Repo] ++ Example.Vault.current().child_specs()

    Supervisor.start_link(children, strategy: :one_for_one, name: Example.Supervisor)
  end
end
