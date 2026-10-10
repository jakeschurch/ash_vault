# Rules for working with AshVault

AshVault encrypts Ash resource attributes at rest, with one key per scope (normally one
per Ash tenant). Destroying a scope's keys makes all of its ciphertext permanently
unreadable, including in every database backup, because the keys never lived in the
database. Read this file in full before touching an encrypted resource.

## Setup

```elixir
# 1. A vault: the key provider plus defaults (AES-256-GCM, tenant scope, manual rotation).
defmodule MyApp.Vault do
  use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
end

# 2. Start the provider and run its one-time setup (see usage-rules/vaults_and_key_providers.md).
children = [MyApp.Repo] ++ MyApp.Vault.child_specs()
:ok = MyApp.Vault.setup()

# 3. A resource.
defmodule MyApp.Accounts.User do
  use Ash.Resource, domain: MyApp.Accounts, data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault MyApp.Vault
    encrypt :email
    encrypt :ssn, encrypt_nil?: false
    decrypt_by_default [:email]
  end

  attributes do
    attribute :email, :string, public?: true   # still declared: gives AshVault the type
    attribute :ssn, :string
  end
end
```

Add `:ash_vault` to `import_deps` in `.formatter.exs`.

## What `encrypt` does to your resource

- `encrypt :email` **removes** the `:email` attribute. It adds a private, sensitive
  `encrypted_email` `:binary` attribute and an `:email` **calculation** that decrypts.
- Migrations/codegen therefore see an `encrypted_email` (`bytea`) column and **no** `email`
  column. Never add a plaintext `email` column by hand.
- Writes still take `email` as an action input; `AshVault.Changes.Encrypt` encrypts it in a
  `before_action` hook (in `atomic/3` for atomic updates) and scrubs the plaintext from the
  changeset.
- Reads: `email` is a calculation. Load it (`Ash.Query.load(query, [:email])`) or list it in
  `decrypt_by_default [:email]`. An unloaded field is `%Ash.NotLoaded{}`, not a value.
- **Do not** filter, sort, aggregate or add identities/custom indexes on an encrypted field.
  The calculation is `filterable?: false, sortable?: false` and ciphertext is randomized.
  Identities or custom indexes naming an encrypted field are a compile-time DSL error.
- **Do not** reference `:email` in `upsert_fields`; use `:encrypted_email` or omit it.

## Migrating an already-encrypted attribute: `legacy:`

```elixir
attribute :api_key, :binary, public?: true, sensitive?: true

encrypt :api_key, legacy: MyApp.Encrypted.Binary, decrypt_for: [MyApp.Checks.System]
```

- Declare the attribute with the type of the AshVault copy; `legacy:` names the type its
  existing column is stored with. Do NOT declare the `vault_<field>` sibling yourself.
- Never add per-action dual-write changes: every create/update that changes the field is
  mirrored automatically, atomically where the action is atomic.
- Do not write the field with `atomic_update/2`, and do not exclude
  `encrypted_vault_<field>` from an upsert that rewrites the field; both are compile errors.
- `decrypt_for` decides who reads the AshVault copy; use `{check, only: [action]}` to
  confine a broad actor (a system actor) to one read action.
- Backfill/verify the copy by its stored name: `--field vault_<field>`.

## Looking up by value: searchable fields

The only way to find rows by an encrypted value is opting in per field:

```elixir
encrypt :email, searchable?: true, unique?: true, normalize: :downcase_trim
```

This adds a deterministic `email_lookup` HMAC column and a generated read action `:by_email`.

```elixir
AshVault.Query.filter_by(MyApp.Accounts.User, :email, "a@b.com", tenant: org_id) |> Ash.read!()
```

- **Never** build or compare tokens by hand, and never filter on `<field>_lookup` directly
  with a hand-made value. Use `AshVault.Query.filter_by/4` or the `:by_<field>` action.
- Searchable fields leak equality (which rows share a value) to anyone with the database.
  Do not make low-cardinality fields (booleans, country, status) searchable.
- Decide `normalize:` before rows exist. Changing it later silently breaks matching.
- `AshVault.KeyProviders.OpenBaoTransit` cannot serve searchable fields.

See `usage-rules/searchable_fields.md`.

## API tokens: macaroons

For API keys or any bearer token naming a record, declare a `macaroon` in `ash_vault`
instead of hand-rolling token hashing or `Vault.mac!/2` schemes. It generates
`:mint_<name>` and `:<name>_by_token` actions. Holders can narrow a token with
`AshVault.Macaroon.attenuate/2`. Revocation works per record (`revoked_when`), per scope
(`:mac` rotation) or by erasure.

- `phase: :authorize` caveats are enforced **only** where policies use
  `AshVault.Checks.MacaroonAllows`. Cover every resource a token actor can reach.
- Caveat checks must only narrow. Never grant more based on a caveat's value.
- With the default `accepted_key_versions 1`, any `:mac` rotation revokes every token in the
  scope.
- `revoked_when` must evaluate to exactly `false` for a live token. `nil` revokes.

See `usage-rules/macaroons.md`.

## A scope is required on every operation

Default scope is the Ash tenant. Every read, write, lookup, rotate and destroy needs one:
`Ash.create!(cs, tenant: org_id)`. Without it you get an error, never an empty result:
`AshVault.Errors.MissingScope` (from `filter_by/4`, the `:by_<field>` action, direct vault
calls), or Ash's own tenant-required error on an Ash-multitenant resource. Not multitenant?
Use `scope: AshVault.Scopes.Global` on the vault **and** `scope :global` on every resource.
Background jobs and scripts need a tenant too.

## Errors: never conflate them

| Error | Meaning | Correct response |
|---|---|---|
| `AshVault.Errors.KeyDestroyed` | Scope was crypto-erased on purpose | Data is gone. Show "deleted"; do not retry |
| `AshVault.Errors.KeyNotFound` | Provider has no such key and no tombstone | Investigate; this is a fault |
| `AshVault.Errors.ProviderUnavailable` | Key store unreachable or failed | Retry, alert. **Not** erasure |
| `AshVault.Errors.ProviderForbidden` | Key store refused the request (`403`) | Alert; fix policy/token/address. **Not** retryable, **not** erasure |
| `AshVault.Errors.CiphertextIntegrityFailed` | Stored bytes do not verify (tamper, wrong tenant/field/key) | Security incident, not a permissions error |

- **Never** treat `ProviderUnavailable` as "erased" or "no data". An outage must not look
  like deletion.
- **Never** `rescue`/`catch` AshVault errors and continue with a blank or default value.
  A swallowed decrypt error is a silent wrong answer.
- Through Ash actions they arrive wrapped in `Ash.Error.Invalid`; match the inner struct in
  `errors`, not the Ash error class. Direct vault/`AshVault.*!` calls raise the struct.

## Rotation and erasure

- `AshVault.rotate_key!(MyApp.Vault, scope)` mints a new key version. Old rows keep
  decrypting; nothing is re-encrypted; lookup tokens are untouched.
- `AshVault.destroy_keys!(MyApp.Vault, scope)` is **irreversible**. Never call it from
  anything a user, test fixture or retry loop can reach without a human decision.
- Keep the key store a different system from the database, excluded from DB backups.

See `usage-rules/rotation_and_erasure.md`.

## Caching and logging

- Key caching (`cache:` on the vault) is **off by default** and should stay off: a cache
  makes erasure that bypasses your vault eventual (within the TTL) instead of immediate.
- Never log, inspect, telemeter or put decrypted values or key material in error text, or
  copy plaintext into other attributes, params or metadata. Generated arguments are
  `sensitive?: true`; keep any you add by hand `sensitive?: true` too.

## Sub-rules

- `usage-rules/dsl.md`: every `ash_vault` DSL option
- `usage-rules/vaults_and_key_providers.md`: vault options, providers, supervision, config
- `usage-rules/searchable_fields.md`: lookups, `unique?`, `normalize:`, `pre_check_with:`
- `usage-rules/rotation_and_erasure.md`: rotate, destroy, tombstones, `key_lifecycle`, mix tasks
- `usage-rules/migrating_from_plaintext.md`: expand / backfill / verify / cut over / contract
- `usage-rules/macaroons.md`: attenuable API tokens, caveats, policies, revocation
- `usage-rules/macs.md`: `mac!/2` and `verify_mac!/4`
- `usage-rules/testing.md`: Memory provider in tests, assertions, pitfalls
