defmodule AshVault.Test.CompositeLegacyCredential do
  @moduledoc false
  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault

    encrypt :token,
      legacy: AshVault.Test.LegacyBinary,
      decrypt_for: [AshVault.Test.Checks.IsSystem]
  end

  ets do
    private? true
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    attribute :group, :string, primary_key?: true, allow_nil?: false, public?: true
    attribute :part, :string, primary_key?: true, allow_nil?: false, public?: true
    attribute :org_id, :string, allow_nil?: false, public?: true
    attribute :token, :binary, public?: true, sensitive?: true
  end

  actions do
    defaults [:read, create: [:group, :part, :org_id, :token]]
  end

  policies do
    policy always() do
      authorize_if AshVault.Test.Checks.IsSystem
    end
  end

  field_policies do
    private_fields :include

    field_policy [:token, :vault_token, :encrypted_vault_token] do
      authorize_if AshVault.Test.Checks.FreshSecretRead
    end

    field_policy :* do
      authorize_if always()
    end
  end
end
