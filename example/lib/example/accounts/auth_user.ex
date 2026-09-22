defmodule Example.Accounts.AuthUser do
  @moduledoc """
  A user you can actually **log in as**, whose email address is encrypted at rest.

  This is the resource searchable fields exist for. A password login has to find a row
  by email before it can check anything, and `WHERE encrypted_email = $1` can never
  match: AES-GCM draws a fresh nonce per write, so the same address encrypts to
  different bytes every time. `searchable?: true` adds the deterministic
  `email_lookup` token beside the ciphertext, and *that* is what the sign-in query
  filters on.

  `unique?: true` adds the identity `:email_lookup_unique` on that token, which gives
  two more things for free:

    * "is this address already taken?" is a real unique index, per tenant
    * `upsert_identity: :email_lookup_unique` makes "create or update this user by
      email" work — see `:register_or_update` below

  ## Why this resource does not use AshAuthentication's `password` strategy

  It uses ash_authentication's password *hashing* (`AshAuthentication.BcryptProvider`,
  the same hash provider the strategy uses by default) but not its
  `authentication do strategies do password ... end` DSL, because that DSL cannot be
  pointed at an AshVault-encrypted field. Three independent things stop it, and all
  three are consequences of the same fact — `AshVault.Transformers.SetupEncryption`
  *removes* the plaintext attribute:

    1. `deps/ash_authentication/lib/ash_authentication/strategies/password/transformer.ex:99-106`
       requires `identity_field` to name an attribute that is uniquely constrained,
       i.e. `identity :unique_email, [:email]`. That identity enforces nothing once the
       attribute is a calculation — it is exactly the construct
       `AshVault.Verifiers.VerifyVault` now rejects.
    2. the register action it generates carries
       `require_attributes: [strategy.identity_field]`
       (`.../password/transformer.ex:201`), and
       `deps/ash/lib/ash/changeset/changeset.ex:4419-4429` dereferences that name as an
       attribute — `BadMapError` on the first registration.
    3. `SignInPreparation` filters `ref(identity_field) == ^identity`
       (`.../password/sign_in_preparation.ex:46`), and the decrypt calculation is
       `filterable?: false` — `Ash.Error.Query.InvalidFilterReference`. A custom sign-in
       action cannot dodge it either: `validate_sign_in_action` *requires* that
       preparation be present (`.../password/transformer.ex:298`).

  Tenant threading, the thing that looked most likely to be the problem, is fine:
  `AshAuthentication.Strategy.Password.Actions.sign_in/3` passes its `options` straight
  into `Ash.Query.for_read/4`
  (`deps/ash_authentication/lib/ash_authentication/strategies/password/actions.ex:47-53`),
  so `tenant:` reaches the query.

  So the actions below are written out by hand. Everything specific to passwords comes
  from ash_authentication; everything specific to finding the row comes from AshVault.
  """

  use Ash.Resource,
    domain: Example.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault &Example.Vault.resolve/2
    scope :tenant

    # `normalize: :downcase_trim` is what makes "  Ada@Acme.INVALID " and
    # "ada@acme.invalid" the same login. It is opt-in on purpose: normalization changes
    # what equality *means* for the column, and changing it after rows exist invalidates
    # every stored token.
    encrypt :email, searchable?: true, unique?: true, normalize: :downcase_trim

    decrypt_by_default [:email]
  end

  postgres do
    table "auth_users"
    repo Example.Repo
  end

  multitenancy do
    strategy :attribute
    attribute :org_id
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :email, :string, public?: true, allow_nil?: false

    attribute :hashed_password, :string do
      allow_nil? true
      sensitive? true
      public? false
    end
  end

  actions do
    defaults [:read, :destroy]

    create :register do
      # `:email` is listed in `accept`, but it does not stay there: AshVault rewrites
      # every action that accepted an encrypted attribute, turning it into a
      # `sensitive?: true` argument backed by `AshVault.Changes.Encrypt` and dropping it
      # from `accept`. Leaving it out of `accept` entirely would mean the action has no
      # way to take an email at all.
      accept [:org_id, :email]

      argument :password, :string, allow_nil?: false, sensitive?: true
      argument :password_confirmation, :string, allow_nil?: false, sensitive?: true

      validate confirm(:password, :password_confirmation)

      change Example.Accounts.HashPassword
    end

    # "Create or update this user by email", keyed on the lookup token rather than on
    # the ciphertext. The identity is the one `unique?: true` generated.
    create :register_or_update do
      accept [:org_id, :email]

      argument :password, :string, allow_nil?: false, sensitive?: true

      upsert? true
      upsert_identity :email_lookup_unique

      change Example.Accounts.HashPassword
    end

    read :sign_in do
      argument :email, :string, allow_nil?: false, sensitive?: true
      argument :password, :string, allow_nil?: false, sensitive?: true

      # AshVault turns the plaintext argument into a filter on `email_lookup`. It is the
      # same preparation backing the `:by_email` action the extension generates, and it
      # resolves the key scope from the query's tenant — so a sign-in with no tenant
      # raises `AshVault.Errors.MissingScope` rather than returning "no such user".
      prepare {AshVault.Preparations.FilterByLookup, field: :email}

      prepare Example.Accounts.VerifyPassword

      get? true
    end
  end
end
