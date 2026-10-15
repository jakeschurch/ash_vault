defmodule AshVault.Test.NativeAliasScope do
  @moduledoc false
  @behaviour AshVault.Scope

  @impl true
  def resolve!(context) do
    AshVault.Scopes.AshTenant.resolve!(context) <> "/" <> to_string(context.field)
  end
end

defmodule AshVault.Test.NativeAliasScopedVault do
  @moduledoc false
  use AshVault.Vault,
    key_provider: AshVault.KeyProviders.Memory,
    scope: AshVault.Test.NativeAliasScope
end

defmodule AshVault.Test.NativeAliasScopedDoc do
  @moduledoc false
  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.NativeAliasScopedVault
    scope AshVault.Test.NativeAliasScope

    encrypt :token,
      stored_as: :vault_token,
      searchable?: true,
      encrypt_nil?: false,
      backfill_from: :source
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
    attribute :source, :string, public?: true
    attribute :token, :string, public?: true, sensitive?: true
  end

  actions do
    default_accept :*
    defaults [:read, create: :*]

    update :update do
      require_atomic? false
    end
  end
end
