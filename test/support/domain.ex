defmodule AshVault.Test.Domain do
  @moduledoc "The Ash domain holding AshVault's extension-layer test resources."

  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(AshVault.Test.Organization)
    resource(AshVault.Test.User)
    resource(AshVault.Test.Contact)
    resource(AshVault.Test.LegacyUser)
    resource(AshVault.Test.AcceptanceUser)
    resource(AshVault.Test.EtsUser)
    resource(AshVault.Test.EtsNote)
    resource(AshVault.Test.EtsTicket)
    resource(AshVault.Test.EtsDynamicVaultUser)
    resource(AshVault.Test.EtsAccount)
    resource(AshVault.Test.EtsContact)
    resource(AshVault.Test.EtsSecretDoc)
    resource(AshVault.Test.SearchUser)
    resource(AshVault.Test.LooseSearchUser)
    resource(AshVault.Test.DedupeUser)
    resource(AshVault.Test.EtsNoLookupDoc)
    resource(AshVault.Test.EtsNonBinaryScopeDoc)
  end
end
