# Mix task family — spec

All operator-facing AshVault operations are Mix tasks under the `ash_vault.` namespace.
The library exposes plain functions too (`AshVault.rotate_key!/2`, `AshVault.destroy_keys!/2`),
but an operator should never have to open IEx to run a migration or a key operation.

| Task | Purpose | Destructive |
|---|---|---|
| `mix ash_vault.backfill` | encrypt an existing plaintext column, online | no (writes ciphertext only) |
| `mix ash_vault.verify` | decrypt a sample and compare against a plaintext column | no |
| `mix ash_vault.key_info` | show a scope's key name, current version, per-version timestamps, tombstone state | no |
| `mix ash_vault.rotate` | rotate a scope's key | no (old ciphertext still decrypts) |
| `mix ash_vault.destroy_keys` | cryptographic erasure for a scope | **YES — irreversible** |

Shared conventions for all of them:

- `--domain`, `--tenant` / `--all-tenants`, `--yes` behave identically everywhere.
- All require the app runtime (`Mix.Task.run("app.start")`) and a reachable key provider;
  all check provider health before doing anything and fail with `ProviderUnavailable`
  rather than doing half the job.
- Non-zero exit on any failure, so they compose in a deploy script.
- One `key=value` line per unit of progress; a human-readable summary last.

## `mix ash_vault.destroy_keys` — the dangerous one

This is the task that makes customer data permanently unreadable. It must:

- print the scope, the resources and fields that will become undecryptable, and the current
  key version, then require the operator to **type the scope back** to confirm — `--yes`
  alone is not enough, and there is no `--force`;
- refuse to run at all unless `MIX_ENV` is explicitly passed or `--i-know-what-this-does` is
  given in production;
- report exactly what it destroyed and confirm the tombstone was written;
- be idempotent — destroying an already-destroyed scope reports that and exits 0.

## `mix ash_vault.backfill`

Turns an existing plaintext column into an encrypted one, online, without a giant
transaction. Implements §20 of the plan: **expand, backfill, cut over, contract**.

## The migration shape this supports

Starting point: `users.email` exists and holds plaintext.

1. **Expand** — add `encrypted_email` (an ordinary Ash/Ecto schema migration, no keys needed)
   and keep `email` as a plain attribute. Do NOT put `email` under `ash_vault` yet.
2. **Deploy** the transitional code: the resource declares
   `encrypt :email_encrypted_target, backfill_from: :email` — or, more simply, the operator
   runs the task with `--from email`. Both writes still go to plaintext.
3. **Backfill** with this task, with the key provider running.
4. **Verify** with `--verify`.
5. **Cut over** — move `:email` under `ash_vault`, so the transformer replaces the attribute
   with the calculation. Reads and writes now go through the vault.
6. **Contract** — drop the plaintext column in a later migration.

The guide must state plainly that step 5 is the irreversible one and should follow a
successful `--verify`, and that schema migrations never need keys while data migration always
does.

### CLI

```
mix ash_vault.backfill MyApp.Accounts.User email [options]

  --from ATTR          plaintext source attribute (default: the field's `backfill_from`)
  --batch-size N       default 500
  --tenant TENANT      required when the key scope is :tenant
  --all-tenants MFA    module/function/arity listing tenants, e.g. MyApp.Accounts.list_tenant_ids/0
  --domain MODULE      Ash domain (inferred when unambiguous)
  --verify             decrypt a sample and compare to the plaintext column; write nothing
  --dry-run            report what would be done; write nothing
  --resume-from ID     start after this primary key
  --yes                skip the confirmation prompt
```

### Behaviour

- Order by primary key ascending; page with a keyset (`pk > last_seen`), never `OFFSET`.
- Filter to rows where the encrypted column `is_nil` — this is what makes the task
  **idempotent** and **resumable** with no state file. A re-run after a crash is a no-op for
  rows already done.
- Each batch is its own transaction. **Never wrap the whole table.**
- Encrypt through the resource's configured vault, using an `%AshVault.Context{}` built from
  the resource, the target field, and the tenant — the same AAD as a normal write, or the
  backfilled rows will not decrypt afterwards. There must be a test asserting a backfilled
  row decrypts through the ordinary read path.
- Write with a bulk update that touches **only** the encrypted column
  (`Ash.bulk_update` with `return_records?: false`), authorize?: false, and an explicit
  `skip_unknown_inputs`. Do not run the resource's normal changes.
- Progress to stdout every batch: rows done, rows remaining, rows/sec, ETA, elapsed.
  Final line is a summary. Keep it parseable — one `key=value` line per batch.
- `--verify` reads a sample (10% or 1000 rows, whichever is smaller, plus the first and last
  row), decrypts, and compares to the plaintext column. Non-zero exit on any mismatch.
- Fail fast: check the provider is reachable **before** the first batch, and surface
  `ProviderUnavailable` as a clear message rather than writing half a table. If the provider
  goes away mid-run, stop at the batch boundary and print the resume command including
  `--resume-from`.
- `--all-tenants` loops tenants sequentially, printing a per-tenant summary. A failure in one
  tenant stops the run and names the tenant.
- Refuse to run when the target field's encrypted column does not exist, or when the field is
  not configured under `ash_vault` — with a message naming the missing piece.

### Non-goals

- No down-migration / decrypt-back mode in v1. If you need one, the plaintext column is still
  there until step 6; say so in the guide.
- No parallelism across batches in v1. It is I/O bound on the provider, and a single ordered
  stream keeps resumability trivially correct.

## Tests

`test/mix/ash_vault_backfill_test.exs`, `@moduletag :postgres`:

- seeds `LegacyUser` rows with plaintext, runs the task, asserts every row has ciphertext and
  that reading through Ash returns the original plaintext
- second run is a no-op (asserts ciphertext bytes unchanged — not merely "still decrypts",
  since re-encrypting would produce a different nonce)
- `--dry-run` writes nothing
- `--verify` passes after a good backfill, and fails (non-zero) when a row is corrupted
- a batch boundary crash (simulate by making the provider fail on batch 2) leaves batch 1
  committed and the printed resume command works
- multi-tenant: two tenants, each backfilled under its own key; cross-tenant read fails
