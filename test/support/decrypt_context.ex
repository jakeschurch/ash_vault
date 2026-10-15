defmodule AshVault.Test.Checks.SameTenant do
  @moduledoc false
  use Ash.Policy.SimpleCheck

  @impl true
  def describe(_opts), do: "actor belongs to the decryption tenant"

  @impl true
  def match?(%{tenant_id: tenant}, %{tenant: tenant, resource: resource} = context, _opts)
      when is_binary(tenant) and is_atom(resource) do
    send(self(), {:decrypt_policy_context, context})
    true
  end

  def match?(_actor, _context, _opts), do: false
end

defmodule AshVault.Test.TenantDecryptDoc do
  @moduledoc false
  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    encrypt :token, decrypt_for: [AshVault.Test.Checks.SameTenant]
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
    attribute :token, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, create: :*]
  end
end

defmodule AshVault.Test.TenantLegacyDecryptDoc do
  @moduledoc false
  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault

    encrypt :token,
      legacy: AshVault.Test.LegacyBinary,
      decrypt_for: [AshVault.Test.Checks.SameTenant]
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
    attribute :token, :binary, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, create: :*]
  end
end
