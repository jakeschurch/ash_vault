# Migrating with `legacy:`

`backfill_from:` migrates a **plaintext** column. When the column is already stored by
another Ash type — an app-level encrypted type under a global key, typically — the
attribute usually has readers and an API contract that must not move while the copy is
being built. `legacy:` is the expand step for that case.

```elixir
attributes do
  # Declared with the type of the AshVault copy.
  attribute :api_key, :binary, public?: true, sensitive?: true
end

ash_vault do
  vault MyApp.Vault
  scope :tenant

  encrypt :api_key,
    legacy: MyApp.Encrypted.Binary,
    encrypt_nil?: false,
    decrypt_for: [MyApp.Checks.IsSystemActor, {MyApp.Checks.Gateway, only: [:read]}]
end
```

## What it generates

| | |
|---|---|
| `api_key` | the original attribute and column, retyped to `MyApp.Encrypted.Binary` — every reader, filter and JSON:API schema stays as it was |
| `encrypted_vault_api_key` | the AshVault ciphertext (`stored_as:` overrides `vault_api_key`; the AEAD binding uses the same name) |
| `vault_api_key` | the private decrypt calculation, of the declared type |
| a global change | on **every** create and update: when the action changes `api_key`, the value is also encrypted into the copy |
| a global preparation | for `decrypt_for` actors, `api_key` reads the decrypted copy when a row has one |

There is nothing to opt into per action. Accepted input, `set_attribute/2`, a custom
change and a value forced in an earlier `before_action` hook are all mirrored; an action
that leaves the attribute alone keeps its ciphertext and stays atomic. An upsert whose
`upsert_fields` lists `api_key` gets `encrypted_vault_api_key` added. The verifier
rejects the two shapes the dual-write cannot follow: `atomic_update/2` on the attribute,
and an upsert that keeps the ciphertext on conflict.

## Values

The copy holds the value **as the legacy type reads it back**: it is dumped and cast
through the legacy type first. A JSON-backed map therefore stores string keys in both
copies, and `mix ash_vault.verify` compares like with like.

## Reads

- `decrypt_for` actors read the AshVault copy. A row without one yet reads the legacy
  value. A decrypt error — `KeyDestroyed`, `ProviderUnavailable`, `ProviderForbidden`,
  integrity — fails the read; it is never answered from the legacy column.
- Everyone else reads the legacy value, subject to your field policies.
- An entry `{check, only: [actions]}` matches only on those read actions, so a broadly
  read resource can decrypt for its system actor on one dedicated action only.
- Skipped: actor-less reads (so verify compares the real legacy column), the row query
  of a bulk update or destroy, and queries that do not select the attribute.

Without `decrypt_for` nothing is swapped: the copy is written and backfilled, but reads
keep the legacy value.

## Backfill and verify

The copy is an ordinary encrypted field named `stored_as`, backfilled from the legacy
attribute:

```bash
mix ash_vault.backfill --resource MyApp.Account --field vault_api_key --tenant acme
mix ash_vault.verify   --resource MyApp.Account --field vault_api_key --tenant acme
```

## Rollback

The legacy column is kept current by every write, so an older release keeps working.
It does not write the copy, though: before rolling forward again, set the ciphertext
column to `NULL` and backfill, or the copy may be older than the legacy value.

## Contract

Once every row verifies, drop the legacy column and replace the declaration with the
end-state form. `stored_as:` is not yet available without `legacy:`; until it is, the
contract step keeps the field named after its ciphertext column.
