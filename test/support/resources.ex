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

defmodule AshVault.Test.EtsAccount do
  @moduledoc """
  Searchable encrypted fields over ETS: one normalized field, one not, one plain
  encrypted field beside them.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :email, searchable?: true, normalize: :downcase_trim
    encrypt :handle, searchable?: true
    encrypt :note
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
    attribute :handle, :string, public?: true
    attribute :note, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*, update: :*]
  end
end

defmodule AshVault.Test.EtsContact do
  @moduledoc """
  A second searchable resource with a field of the same name, so a token proves it is
  bound to its resource and not just to its field name.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :email, searchable?: true, normalize: :downcase_trim
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

defmodule AshVault.Test.EtsSecretDoc do
  @moduledoc """
  Tenant-scoped searchable encryption on a resource that is *not* multitenant in Ash.

  Ash rejects a tenant-less query on a multitenant resource before any preparation runs,
  so this is the only place the "a lookup with no tenant must not return an empty
  result" guarantee can actually be observed.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :label, searchable?: true
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :label, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*, update: :*]
  end
end

defmodule AshVault.Test.SearchUser do
  @moduledoc """
  The Postgres-backed searchable resource: `unique?` enforcement, the real unique index,
  and the `EXPLAIN` assertion that a lookup actually uses it.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :email, searchable?: true, unique?: true, normalize: :downcase_trim
  end

  postgres do
    table "search_users"
    repo AshVault.Test.Repo
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
    defaults [:read, :destroy, create: :*, update: :*]

    # Upsert by an encrypted field. The identity is the one
    # `AshVault.Transformers.SetupEncryption` generates for `unique?: true`, so the
    # ON CONFLICT target is the lookup token — never the randomized ciphertext.
    create :upsert_by_email do
      accept [:org_id, :name, :email]
      upsert? true
      upsert_identity :email_lookup_unique
    end
  end
end

defmodule AshVault.Test.LooseSearchUser do
  @moduledoc """
  The same `search_users` table and the same field, with a *different* `normalize:`.

  It exists to demonstrate the one thing SEARCHABLE_SPEC warns about loudest: changing
  `normalize:` after rows exist changes every token, so a row written under one strategy
  is invisible to a lookup — and to an upsert — under the other.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :email, searchable?: true, unique?: true, normalize: :none
  end

  postgres do
    table "search_users"
    repo AshVault.Test.Repo
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
    defaults [:read, :destroy, create: :*, update: :*]

    create :upsert_by_email do
      accept [:org_id, :name, :email]
      upsert? true
      upsert_identity :email_lookup_unique
    end
  end
end

defmodule AshVault.Test.DedupeUser do
  @moduledoc """
  A searchable field with no `unique?`, over its own table with a non-unique index.

  This is what a table looks like before anyone adds the constraint, and it is the only
  shape in which the `GROUP BY <field>_lookup` dedupe recipe has anything to find.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Vault
    scope :tenant

    encrypt :email, searchable?: true, normalize: :downcase_trim
  end

  postgres do
    table "dedupe_users"
    repo AshVault.Test.Repo
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
    defaults [:read, :destroy, create: :*, update: :*]
  end
end

defmodule AshVault.Test.EtsNoLookupDoc do
  @moduledoc """
  A searchable field on a resource whose vault is a `fun/2`, so the verifier cannot see
  the key provider at compile time.

  This is the one shape that reaches `AshVault.Errors.LookupUnsupported` at runtime, and
  it exists to prove that backstop is a clean, permanent configuration error rather than a
  retryable `ProviderUnavailable` or an `UndefinedFunctionError` out of a hook.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault &AshVault.Test.Support.NoLookupVaultResolver.resolve/2
    scope :global

    encrypt :label, searchable?: true
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :label, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*, update: :*]
  end
end

defmodule AshVault.Test.EtsNonBinaryScopeDoc do
  @moduledoc """
  A searchable resource whose vault's `AshVault.Scope` returns a non-binary.

  It exists for one regression. `AshVault.Lookup.field_key/3` used to call
  `scope.resolve!/1` directly rather than going through
  `AshVault.Vault.Runtime.resolve_scope!/3`, so the binary-scope invariant failed here as
  a bare `ArgumentError` out of the provider's own `validate_scope!/1` — a wrong-shaped
  error escaping a non-bang `Ash.read/2` — instead of the `AshVault.Errors.InvalidScope`
  every other path in the library raises.
  """

  use Ash.Resource,
    domain: AshVault.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshVault]

  ash_vault do
    vault AshVault.Test.Support.NonBinaryScopeVault
    # Must match the vault's own scope, or `AshVault.Verifiers.VerifyVault` rejects the
    # resource at compile time — rotation and erasure would otherwise act on other keys.
    scope AshVault.Test.Support.NonBinaryScope

    encrypt :email, searchable?: true
  end

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
    attribute :email, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*, update: :*]
  end
end
