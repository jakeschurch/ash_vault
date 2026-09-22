defmodule Example.Accounts.Organization do
  @moduledoc """
  The tenant. It *owns* the encryption scope, so this is where key lifecycle lives.

  ## Why lifecycle belongs here and not on `User`

  The key scope is `:tenant`, so every encrypted field on every tenant-scoped resource
  in this domain — `User.email`, `Contact.phone` — is encrypted under **one** key per
  organization. "Rotate" and "crypto-erase" are therefore operations on the
  organization, not on a resource that happens to have an encrypted field. Putting
  `key_lifecycle` on `User` would let you "rotate the users' key", which is a
  misdescription: you would also be rotating the contacts' key, because it is the same
  key. AshVault enforces this by requiring `scope_owner? true` for `key_lifecycle`.

  The generated `:rotate_key` and `:destroy_keys` are ordinary Ash generic actions, so
  the policies below govern them exactly as they would any other action. AshVault adds
  no authorization of its own — crypto-erasing a tenant is as guarded as you make it.
  """

  use Ash.Resource,
    domain: Example.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault &Example.Vault.resolve/2
    scope :tenant
    scope_owner? true

    key_lifecycle do
      rotate :rotate_key
      destroy :destroy_keys
    end
  end

  postgres do
    table "organizations"
    repo Example.Repo
  end

  attributes do
    uuid_primary_key :id
    attribute :name, :string, public?: true
  end

  actions do
    default_accept [:name]
    defaults [:read, :destroy, create: :*, update: :*]
  end

  policies do
    # Key lifecycle is destructive and irreversible. Only an admin actor may reach it.
    policy action([:rotate_key, :destroy_keys]) do
      authorize_if actor_attribute_equals(:admin?, true)
    end

    policy always() do
      authorize_if always()
    end
  end
end
