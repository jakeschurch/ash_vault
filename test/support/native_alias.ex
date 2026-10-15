defmodule AshVault.Test.NativeAliasDoc do
  @moduledoc false
  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    encrypt :token, stored_as: :vault_token, decrypt_for: [AshVault.Test.Checks.SameTenant]
    encrypt :other, stored_as: :vault_other

    encrypt :action_only,
      stored_as: :vault_action_only,
      decrypt_for: [{AshVault.Test.Checks.IsSystem, only: [:credentials]}]
  end

  ets do
    private? true
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :string, allow_nil?: false, public?: true
    attribute :token, :binary, public?: true, sensitive?: true
    attribute :other, :binary, public?: true, sensitive?: true
    attribute :action_only, :binary, public?: true, sensitive?: true
  end

  actions do
    default_accept :*
    defaults [:read, create: :*]

    read :credentials do
    end

    update :update do
      require_atomic? false
    end
  end
end

defmodule AshVault.Test.NativeAliasPgAccount do
  @moduledoc false
  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    encrypt :token, stored_as: :vault_token, encrypt_nil?: false
  end

  postgres do
    table "legacy_accounts"
    repo AshVault.Test.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :name, :string, allow_nil?: false, public?: true
    attribute :token, :binary, public?: true, sensitive?: true
  end

  identities do
    identity :unique_name, [:name]
  end

  actions do
    default_accept :*
    defaults [:read, create: :*]

    update :update do
      require_atomic? false
    end

    update :replace_token do
      accept [:token]
    end

    create :upsert do
      upsert? true
      upsert_identity :unique_name
      upsert_fields [:encrypted_vault_token]
    end
  end
end
