defmodule AshVault.Test.Profile do
  @moduledoc "Embedded resource used as the type of an encrypted attribute."

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute(:nickname, :string, public?: true)
    attribute(:age, :integer, public?: true)
  end
end

defmodule AshVault.Test.Organization do
  @moduledoc """
  The tenant resource. It owns the key scope, so it is where `key_lifecycle` lives.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    scope(:tenant)
    scope_owner?(true)

    key_lifecycle do
      rotate(:rotate_key)
      destroy(:destroy_keys)
    end
  end

  postgres do
    table("organizations")
    repo(AshVault.Test.Repo)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:name, :string, public?: true)
  end

  actions do
    default_accept([:name])
    defaults([:read, :destroy, create: :*, update: :*])
  end
end

defmodule AshVault.Test.User do
  @moduledoc """
  The main test resource: tenant-scoped encryption over a scalar, a nil-able scalar with
  `encrypt_nil?: false`, an embedded resource, an array of scalars and an array of
  embedded resources.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    scope(:tenant)

    encrypt(:email)
    encrypt(:ssn, encrypt_nil?: false)
    encrypt(:profile)
    encrypt(:contacts)

    attributes([:tags])

    decrypt_by_default([:email])
  end

  postgres do
    table("users")
    repo(AshVault.Test.Repo)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:org_id, :uuid, allow_nil?: false, public?: true)
    attribute(:name, :string, public?: true)
    attribute(:email, :string, public?: true)
    attribute(:ssn, :string, public?: true, allow_nil?: true)
    attribute(:profile, AshVault.Test.Profile, public?: true)
    attribute(:tags, {:array, :string}, public?: true)
    attribute(:contacts, {:array, AshVault.Test.Profile}, public?: true)
  end

  actions do
    default_accept(:*)
    defaults([:read, :destroy])

    create :create do
      primary?(true)
    end

    update :update do
      primary?(true)
      require_atomic?(false)
    end

    # Same accept list, but left atomic so `AshVault.Changes.Encrypt.atomic/3` runs.
    update :update_atomic do
      require_atomic?(true)
    end
  end

  policies do
    policy always() do
      authorize_if(always())
    end
  end

  field_policies do
    # Only an admin actor may see the decrypted email.
    field_policy :email do
      authorize_if(actor_attribute_equals(:admin?, true))
    end

    field_policy :* do
      authorize_if(always())
    end
  end
end

defmodule AshVault.Test.Contact do
  @moduledoc """
  A second tenant-scoped resource, proving one tenant key spans resources while the AAD
  still separates their ciphertext.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    attributes([:phone])
  end

  postgres do
    table("contacts")
    repo(AshVault.Test.Repo)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:org_id, :uuid, allow_nil?: false, public?: true)
    attribute(:phone, :string, public?: true)
  end

  actions do
    default_accept(:*)
    defaults([:read, :destroy, create: :*, update: :*])
  end
end

defmodule AshVault.Test.EtsUser do
  @moduledoc """
  An ETS-backed twin of `AshVault.Test.User`.

  It exercises the whole write/read path — serialization, scrubbing, nil handling, error
  surfacing — with no database, so the bulk of the extension suite runs without Docker.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    scope(:tenant)

    encrypt(:email)
    encrypt(:ssn, encrypt_nil?: false)
    encrypt(:profile)
    encrypt(:contacts)

    attributes([:tags])
  end

  ets do
    private?(true)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:org_id, :string, allow_nil?: false, public?: true)
    attribute(:name, :string, public?: true)
    attribute(:email, :string, public?: true)
    attribute(:ssn, :string, public?: true)
    attribute(:profile, AshVault.Test.Profile, public?: true)
    attribute(:tags, {:array, :string}, public?: true)
    attribute(:contacts, {:array, AshVault.Test.Profile}, public?: true)
  end

  actions do
    default_accept(:*)
    defaults([:read, :destroy])

    create :create do
      primary?(true)
    end

    update :update do
      primary?(true)
      require_atomic?(false)
    end
  end
end

defmodule AshVault.Test.EtsNote do
  @moduledoc "Globally-scoped encryption: one key lineage for the whole application."

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.GlobalVault)
    scope(:global)

    encrypt(:body)
  end

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:body, :string, public?: true)
  end

  actions do
    default_accept(:*)
    defaults([:read, :destroy, create: :*, update: :*])
  end
end

defmodule AshVault.Test.EtsTicket do
  @moduledoc """
  Tenant-scoped encryption on a resource that is *not* multitenant in Ash.

  Ash itself rejects a tenant-less changeset on a multitenant resource before any change
  runs, so this is where `AshVault.Errors.MissingScope` can actually be observed coming
  out of the encrypt change.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault(AshVault.Test.Vault)
    scope(:tenant)

    encrypt(:secret)
  end

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:secret, :string, public?: true)
  end

  actions do
    default_accept(:*)
    defaults([:read, :destroy, create: :*, update: :*])
  end
end

defmodule AshVault.Test.EtsDynamicVaultUser do
  @moduledoc """
  A resource whose `vault` is a `fun/2` rather than a module.

  It proves the dynamic vault forms are reached — and that both the write and read paths
  hand them the same normalized `ash_context` map.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault &AshVault.Test.DynamicVault.resolve/2

    encrypt :email
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
    attribute :email, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*, update: :*]
  end
end
