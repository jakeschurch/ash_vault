defmodule Example.Accounts.Contact do
  @moduledoc """
  A *second* tenant-scoped resource with an encrypted field.

  This is the point of the example. `Contact.phone` and `User.email` are encrypted
  under the same per-organization key, because the key scope is the tenant. That is
  why `key_lifecycle` lives on `Example.Accounts.Organization` — rotating or erasing
  "the organization's key" moves both resources at once.

  The two resources' ciphertext is still not interchangeable: the AAD (additional
  authenticated data) the cipher binds includes the resource module and the field name
  alongside the scope, so a `User.email` envelope pasted into `Contact.encrypted_phone`
  fails authentication rather than decrypting. One key, but per-field binding.

  `attributes [:phone]` is shorthand for `encrypt :phone` with default options.
  """

  use Ash.Resource,
    domain: Example.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault &Example.Vault.resolve/2
    # Stated explicitly rather than relying on the `:tenant` default, because "which
    # key does this row use" is the single most important fact about the resource.
    scope :tenant

    attributes [:phone]

    decrypt_by_default [:phone]
  end

  postgres do
    table "contacts"
    repo Example.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :label, :string, public?: true
    attribute :phone, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*, update: :*]
  end
end
