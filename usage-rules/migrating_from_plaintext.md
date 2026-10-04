# Migrating an existing plaintext column

Online, no maintenance window: **expand, deploy, backfill, verify, cut over, contract**.
Schema migrations never need keys; the backfill always does (running app, reachable provider).

## 1. Expand (ordinary migration)

`encrypt :email` removes the `:email` attribute, so a plaintext `email` column and the field
cannot coexist. Rename it out of the way and add the ciphertext column:

```elixir
rename table(:users), :email, to: :legacy_email
alter table(:users), do: add(:encrypted_email, :binary)
```

Deploy this alone first. (Searchable? Also add `email_lookup` as `:binary` plus an index.)

## 2. Deploy the transitional resource

```elixir
ash_vault do
  vault MyApp.Vault
  encrypt :email, backfill_from: :legacy_email
end

attributes do
  attribute :legacy_email, :string, public?: true
  attribute :email, :string, public?: true
end
```

From this deploy, writes to `:email` land in `encrypted_email` and `legacy_email` goes stale.
Move reads onto `:email` (a calculation: load it or use `decrypt_by_default`).

## 3. Backfill

```bash
mix ash_vault.backfill MyApp.Accounts.User email --tenant acme --dry-run
mix ash_vault.backfill MyApp.Accounts.User email --tenant acme
mix ash_vault.backfill MyApp.Accounts.User email --all-tenants MyApp.Accounts.list_tenant_ids/0 --batch-size 1000 --yes
```

Options: `--from ATTR`, `--batch-size N` (default 500), `--tenant`, `--all-tenants MFA`,
`--domain`, `--action NAME` (update action; must be `require_atomic? false`), `--dry-run`,
`--verify`, `--resume-from ID` (one tenant only), `--sample N`, `--yes`, `--lookup`.

- Idempotent and resumable with no state file: it only touches rows whose encrypted column is
  NULL. Re-running is safe; if it stops, it prints the exact resume command.
- Each batch is its own transaction. The table is never locked in one.
- Do not combine `--all-tenants` with `--resume-from` (refused).
- Do not pass the `encrypted_<field>` column as `--from`/`backfill_from` (refused).
- `--lookup` fills tokens for rows that already hold ciphertext (after adding `searchable?`).
  It never rewrites ciphertext and refuses if `normalize:` changed on a populated column.
- From code: `AshVault.Backfill.run(MyApp.Accounts.User, :email, tenant: "acme", from: :legacy_email)`
  returns `{:ok, stats}`, `{:error, exception}` (bad plan or provider preflight) or
  `{:error, exception, stats}` (a batch failed) (usable in a release without Mix).
- Pass `--tenant` or `--all-tenants` (not both) for a `scope :tenant` resource; omit both
  only for `scope :global`.

## 4. Verify, then do not skip it

```bash
mix ash_vault.verify MyApp.Accounts.User email --tenant acme --sample 0
```

Decrypts rows and compares with the plaintext column (and recomputes lookup tokens for
searchable fields). Non-zero exit on any mismatch. Run `--sample 0` (every row) once per
tenant before cut-over. Do **not** continue past mismatches; null out the affected rows'
`encrypted_<field>` and re-run the backfill for them.

## 5. Cut over (point of no return for that data)

Move every reader/writer, job, export and admin tool onto `:email` with a tenant. After a
clean verify, the ciphertext is the only copy; there is no decrypt-back mode. The plaintext
column is your sole rollback until step 6, and losing the key store now loses the data.
Watch for `AshVault.Errors.MissingScope` (or Ash's tenant-required error on a multitenant
resource) from jobs/scripts that read without a tenant.

## 6. Contract

Drop `legacy_email` in a later migration; remove `backfill_from` and the `legacy_email`
attribute in the same deploy.

Backups taken before this migration still hold plaintext, and crypto-erasure cannot reach
them. Age them out if historical plaintext matters.

## Don't

- Don't run the backfill without a reachable provider or without verifying key setup first
  (`mix ash_vault.key_info`).
- Don't pick the scope or `normalize:` casually: changing the scope re-keys everything and
  changing `normalize:` orphans tokens.
- Don't make a field `unique?: true` until the backfill is done, and check duplicates first:
  `GROUP BY email_lookup HAVING count(*) > 1`.
