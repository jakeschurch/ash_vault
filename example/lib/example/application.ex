defmodule Example.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [Example.Repo] ++ key_provider_children()

    Supervisor.start_link(children, strategy: :one_for_one, name: Example.Supervisor)
  end

  # The OpenBao provider is stateless (plain HTTP calls), so it needs no child. The
  # Local provider is a GenServer that serializes every mutation of the key directory,
  # so it has to be supervised — and it refuses to start on a root it did not see
  # initialised, which is what stops an unmounted key volume from looking like a
  # pristine, never-used key store. `mix example.setup` runs `init_root!/1`.
  defp key_provider_children do
    case Example.Vault.key_provider() do
      AshVault.KeyProviders.Local -> [AshVault.KeyProviders.Local]
      _ -> []
    end
  end
end
