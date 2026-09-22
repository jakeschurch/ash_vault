defmodule Example.Accounts.User do
  @moduledoc """
  A tenant-scoped resource with one encrypted field.

  `encrypt :email` *replaces* the `:email` attribute: the plaintext attribute is
  removed from the resource, a private `encrypted_email` `:binary` attribute takes its
  place in the data layer, and a calculation named `:email` decrypts on read. There is
  no plaintext column, so no data layer can write one.

  `decrypt_by_default [:email]` means a plain `Ash.read` loads the decrypt calculation
  without an explicit `Ash.Query.load/2`.
  """

  use Ash.Resource,
    domain: Example.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault &Example.Vault.resolve/2
    scope :tenant

    encrypt :email

    decrypt_by_default [:email]
  end

  postgres do
    table "users"
    repo Example.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :name, :string, public?: true
    attribute :email, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy]

    create :create do
      primary? true
    end

    update :update do
      primary? true
      require_atomic? false
    end
  end

  policies do
    policy always() do
      authorize_if always()
    end
  end

  field_policies do
    # Field policies apply to the *decrypt calculation*, because that is what the
    # encrypted field became. A denied field comes back as `%Ash.ForbiddenField{}`,
    # and the decrypt calculation passes that straight through rather than trying to
    # decrypt it — authorization and encryption compose instead of fighting.
    #
    # Note field policies may only use filter or simple checks; anything else raises.
    field_policy :email do
      authorize_if actor_attribute_equals(:admin?, true)
    end

    field_policy :* do
      authorize_if always()
    end
  end
end
