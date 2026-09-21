# Test harness & acceptance tests — spec

## Infrastructure (already running, verified)

| Service | Where | Credentials |
|---|---|---|
| PostgreSQL 16 (pgvector image) | `localhost:5432`, container `foundrybox-postgres-1` | user `postgres`, password `postgres` |
| OpenBao 2.6.2 (dev mode) | `http://127.0.0.1:8200`, container `ashvault-bao` | token `ashvault-root` |

The test database is **`ash_vault_test`** — created by the harness, never `foundry_dev`.
Nothing in this repo may touch `foundry_dev`.

Config lives in `config/test.exs`; the repo is `AshVault.Test.Repo` in `test/support/`.
`mix test` must work with no Docker for every suite except those tagged `:postgres` or
`:openbao`; those are excluded by default in `test/test_helper.exs`:

```elixir
ExUnit.start(exclude: [:postgres, :openbao])
```

and run with `mix test --include postgres --include openbao`. Provide mix aliases:

```elixir
"test.all": ["test --include postgres --include openbao"],
"test.ci":  ["test"]
```

## Test resources (`test/support/`)

```
AshVault.Test.Repo          AshPostgres.Repo
AshVault.Test.Domain        Ash.Domain
AshVault.Test.Vault         use AshVault.Vault, key_provider: AshVault.KeyProviders.Memory
AshVault.Test.LocalVault    use AshVault.Vault, key_provider: AshVault.KeyProviders.Local
AshVault.Test.BaoVault      use AshVault.Vault, key_provider: AshVault.KeyProviders.OpenBao
AshVault.Test.Organization  tenant resource, scope_owner? true, key_lifecycle actions
AshVault.Test.User          encrypted :email, :ssn; embedded + array attrs; field policies
AshVault.Test.Contact       encrypted :phone — proves one tenant key spans resources
AshVault.Test.Profile       embedded resource with an encrypted attribute
AshVault.Test.LegacyUser    plaintext :email still present, for the backfill task test
```

Multitenancy: use **attribute** multitenancy (`org_id`) rather than schema-per-tenant — it
keeps `pg_dump`/restore in the acceptance test to a single schema and makes cross-tenant
ciphertext substitution expressible as a plain UPDATE.

## §27 Backup–restore acceptance test — MANDATORY

File: `test/acceptance/backup_restore_test.exs`, tagged `@moduletag :postgres` and
`@moduletag :openbao`.

**This test must NOT run against `AshVault.KeyProviders.Memory`** — Memory's keys were never
in PostgreSQL, so it passes vacuously and proves nothing. Run it twice, parameterized:

- once against `AshVault.KeyProviders.OpenBao` (keys in OpenBao — the convincing case)
- once against `AshVault.KeyProviders.Local` with its root in a `tmp_dir` **outside** the
  directory that gets backed up (keys on disk, deliberately excluded from the DB backup)

Steps:

1. Create tenant A and tenant B. Write encrypted rows for each.
2. Assert A decrypts; assert B decrypts.
3. Take a real backup: `pg_dump` the test database to a file
   (`System.cmd("pg_dump", [...])` against the container, or `docker exec`). A `COPY`-based
   dump is fine; it must be a genuine file on disk, not an in-transaction savepoint.
4. Assert the dump file contains **no plaintext** — grep the raw bytes for the plaintext
   email and SSN values and assert zero hits.
5. `AshVault.destroy_keys!(vault, tenant_a_scope)`.
6. Assert reading A's rows returns `AshVault.Errors.KeyDestroyed` (not
   `AuthenticationFailed`, not a raised exception). Assert B still decrypts.
7. Restore the dump into the test database (drop + recreate + `psql -f`), i.e. the state from
   **before** the destruction.
8. Assert A's rows are present again as rows, and that reading them **still** returns
   `KeyDestroyed`. Assert B still decrypts.

Step 8 is the whole library. If it fails, the design has failed.

## §28 Rotation acceptance test

File: `test/acceptance/rotation_test.exs`.

1. Tenant B, key v1. Write row 1.
2. Assert the stored envelope decodes with `key_version: 1` (decode the raw column bytes with
   `AshVault.Envelope.decode/1` — do not infer).
3. `AshVault.rotate_key!(vault, scope)` → v2. Write row 2.
4. Assert row 2's envelope carries `key_version: 2`; assert row 1's still carries 1.
5. Assert both rows decrypt.
6. Rotate again to v3, write row 3, assert all three decrypt and carry versions 1, 2, 3.
7. Destroy. Assert all three now return `KeyDestroyed`.

## Definition-of-Done checklist test

File: `test/acceptance/definition_of_done_test.exs` — one test per numbered item in §32 of
the plan, each with a comment naming the item. This is the artifact that answers "is it done"
without re-reading the whole suite.

Items 7 and 8 (cross-tenant and cross-field ciphertext substitution) are expressed as direct
SQL UPDATEs through `Postgrex` that move a ciphertext blob, followed by an `Ash.read` that
must return `AuthenticationFailed`.

Item 4 (DB contains no plaintext) is a `Postgrex` query reading the raw column, asserting the
bytes start with the `"AV"` envelope magic and contain no substring of the plaintext.

Item 17 (backfill) runs `mix ash_vault.backfill` programmatically against `LegacyUser`.
