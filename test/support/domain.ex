defmodule AshVault.Test.Domain do
  @moduledoc "The Ash domain holding AshVault's extension-layer test resources."

  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(AshVault.Test.Organization)
    resource(AshVault.Test.User)
    resource(AshVault.Test.Contact)
    resource(AshVault.Test.EtsUser)
    resource(AshVault.Test.EtsNote)
    resource(AshVault.Test.EtsTicket)
    resource(AshVault.Test.EtsDynamicVaultUser)
  end
end
