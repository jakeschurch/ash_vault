# Migrating from plaintext

You have a `users.email` column full of plaintext and a production system reading and
writing it. This is how you get it encrypted without a maintenance window and without a
giant transaction.

The shape is the standard four-phase online migration: **expand, backfill, cut over,
contract**. Two rules govern the whole thing:

* **Schema migrations never need keys.** Adding `encrypted_email` is an ordinary Ash/Ecto
  migration.
* **Data migrations always need keys.** The backfill needs the app runtime and a reachable
  key provider, and it fails fast with `ProviderUnavailable` rather than writing half a
  table.

## Before you start

* The key provider is running and reachable, and `mix ash_vault.key_info` answers for the
  tenants you are about to migrate.
* You have decided on your scope. Changing it later re-keys everything.
* You have a database backup taken *before* the migration, and you know it contains
  plaintext. Contracting (step 5) does not remove plaintext from backups you already
  took; only key destruction can reach those, and it cannot — those rows were never
  encrypted. If your goal is to make *historical* plaintext unreadable, the migration is
  necessary but not sufficient: you also have to age out the backups that predate it.

## Step 1 — Expand

Rename the plaintext column out of the way and add the ciphertext column. One migration,
no keys:

```elixir
defmodule MyApp.Repo.Migrations.ExpandUserEmail do
  use Ecto.Migration

  def change do
    rename table(:users), :email, to: :legacy_email
    alter table(:users), do: add(:encrypted_email, :binary)
  end
end
```

The rename is what makes the rest work. The AshVault transformer *removes* the `:email`
attribute and replaces it with a calculation, so `:email` and a plaintext `email` column
cannot coexist — and `mix ash_vault.backfill` refuses a source that is the ciphertext
attribute. The plaintext has to live under a different name until you drop it.

> If you would rather not rename, the alternative is to encrypt under a *new* field name
> (`encrypt :email_v2, backfill_from: :email`) and rename the field in your application
> code instead. Same tradeoffs, different place to do the renaming. Everything below
> assumes the rename.

Deploy the migration on its own first. Nothing reads or writes the new column yet.

## Step 2 — Deploy the transitional resource

Now put the field under `ash_vault`, alongside the surviving plaintext attribute:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    domain: MyApp.Accounts,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshVault]

  ash_vault do
    vault MyApp.Vault
    scope :tenant

    encrypt :email, backfill_from: :legacy_email
  end

  attributes do
    uuid_primary_key :id
    attribute :org_id, :uuid, allow_nil?: false, public?: true
    attribute :legacy_email, :string, public?: true
    attribute :email, :string, public?: true
  end

  actions do
    default_accept :*
    defaults [:read, :destroy, create: :*]

    update :update do
      primary? true
      require_atomic? false
    end
  end
end
```

`backfill_from: :legacy_email` records the source in the resource, so
`mix ash_vault.backfill` and `mix ash_vault.verify` do not need `--from`. The verifier
checks it names an attribute that still exists.

> #### This deploy changes write behaviour {: .warning}
>
> From this moment, writes to `:email` go through the vault and land in
> `encrypted_email`. `legacy_email` stops being updated. Rows written from here on are
> already encrypted; the backfill is only for the rows that predate this deploy.
>
> If your application still reads `legacy_email` anywhere, those reads now see stale
> values for newly-written rows. Move reads onto `:email` in this deploy or the one after,
> and remember `:email` has to be loaded — it is a calculation:
>
> ```elixir
> MyApp.Accounts.User |> Ash.Query.load([:email]) |> Ash.read!(tenant: org.id)
> ```
>
> `decrypt_by_default [:email]` makes that automatic if you prefer.

## Step 3 — Backfill

```
mix ash_vault.backfill MyApp.Accounts.User email --tenant acme
```

```
Encrypt MyApp.Accounts.User.email for 1 tenant(s)? [Yn] y
ash_vault.backfill=start resource=MyApp.Accounts.User field=email source=legacy_email \
  tenant=acme scope=acme vault=MyApp.Vault provider=AshVault.KeyProviders.OpenBao \
  key=v1 rows=2000 batch_size=500 dry_run=false
batch=1 rows=500 done=500 skipped=0 remaining=1500 rate=812.3 eta_s=1.8 elapsed_s=0.62 last_pk=...
batch=2 rows=500 done=1000 skipped=0 remaining=1000 rate=830.1 eta_s=1.2 elapsed_s=1.20 last_pk=...
batch=3 rows=500 done=1500 skipped=0 remaining=500 rate=835.7 eta_s=0.6 elapsed_s=1.79 last_pk=...
batch=4 rows=500 done=2000 skipped=0 remaining=0 rate=838.2 eta_s=0.0 elapsed_s=2.38 last_pk=...
ash_vault.backfill=done rows=2000 done=2000 skipped=0 batches=4 elapsed_s=2.38
Backfilled 2000 row(s) of MyApp.Accounts.User.email for tenant acme in 4 batch(es) (2.38s).
```

Every flag:

```
mix ash_vault.backfill RESOURCE FIELD [options]

  --from ATTR          plaintext source attribute (default: the field's `backfill_from`)
  --batch-size N       rows per committed transaction (default 500)
  --tenant TENANT      required when the key scope is `:tenant`
  --all-tenants MFA    zero-arity Module.function/0 listing tenants
  --domain MODULE      Ash domain (inferred from `:ash_domains` when omitted)
  --action NAME        update action to write with (default: the primary update action;
                       it must be `require_atomic? false`)
  --verify             decrypt a sample and compare to the plaintext column; write nothing
  --dry-run            report what would be done; write nothing
  --resume-from ID     start after this primary key
  --sample N           rows to check in `--verify` mode (`0` checks every row)
  --yes                skip the confirmation prompt
```

Across every tenant:

```
mix ash_vault.backfill MyApp.Accounts.User email \
  --all-tenants MyApp.Accounts.list_tenant_ids/0 --batch-size 1000 --yes
```

A failure in one tenant stops the run and names that tenant.

### What it guarantees

* **Idempotent and resumable with no state file.** Rows are selected with
  `encrypted_email IS NULL`, ordered by primary key, paged with a keyset (`pk > last_seen`)
  rather than `OFFSET`. An encrypted row no longer matches the filter, so a second run is a
  no-op — and asserted so in the test suite by comparing ciphertext *bytes*, not merely
  "it still decrypts" (re-encrypting would produce a different nonce).
* **Each batch is its own transaction.** The table is never wrapped in one.
* **Only the encrypted column is written.** One `Ash.bulk_update/4` per batch, with
  `authorize?: false` and `return_records?: false`.
* **Backfilled rows decrypt through the ordinary read path.** The context is built by the
  same `AshVault.Context.Builder.from_changeset/3` an ordinary write uses, from a real
  changeset over the real record, with the plaintext *field* name — so the AAD matches. A
  backfill that hand-rolled its context would be one field name away from writing rows that
  never decrypt again, which is why there is a test asserting exactly this.
* **The provider is checked before the first batch.** An unreachable provider fails
  immediately rather than half-writing the table.

If the provider goes away mid-run, the task stops at a batch boundary and prints the exact
command to resume:

```
Stopped at a batch boundary. 1000 row(s) are committed; the rest are untouched.
Resume with:

    mix ash_vault.backfill MyApp.Accounts.User email --batch-size 500 --tenant acme --resume-from 4a1f...
```

`--resume-from` is an optimisation that skips re-scanning the committed prefix, never a
correctness requirement: the `IS NULL` filter already makes a plain re-run correct.

### Nil sources

When the field is `encrypt_nil?: false`, a `nil` source legitimately stores SQL NULL — so
those rows would match the `IS NULL` filter forever. They are excluded with
`source IS NOT NULL` and counted separately:

```
Backfilled 1988 row(s) of MyApp.Accounts.User.email in 4 batch(es) (2.38s), 12 row(s) skipped (nil source, `encrypt_nil?: false`).
```

### Dry run first

```
mix ash_vault.backfill MyApp.Accounts.User email --tenant acme --dry-run
```

Writes nothing, and specifically does not mint key material — an unused scope reports
`key=not_minted` rather than being created.

## Step 4 — Verify

```
mix ash_vault.verify MyApp.Accounts.User email --tenant acme
```

```
ash_vault.verify=result resource=MyApp.Accounts.User field=email rows=2000 checked=200 mismatches=0
Verified 200 of 2000 row(s) of MyApp.Accounts.User.email: no mismatches.
```

It decrypts a sample and compares to the plaintext column. The default sample is 10% of
the table or 1000 rows, whichever is smaller, always including the first and the last row;
`--sample 0` checks every row. It writes nothing.

Exit status is non-zero on the first tenant with any mismatch — a row whose ciphertext is
NULL, whose plaintext differs, or which fails to decrypt at all — and the summary names
the offending primary keys.

Run `--sample 0` at least once per tenant before you contract. It is the last cheap check
you get.

## Step 5 — Cut over

Move every reader and writer onto `:email`. Delete any code still touching
`legacy_email`. Make sure background jobs, exports, admin tooling and reports go through
`Ash.Query.load([:email])` with a tenant.

> #### This is the point of no return for that attribute {: .error}
>
> Once the attribute lives under `ash_vault` and nothing writes the plaintext column any
> more, the ciphertext is the only copy of the data. There is **no decrypt-back mode** in
> v1 and no `mix ash_vault.decrypt`. Do this only after a clean `--verify`, and only when
> you are confident the key provider is production-ready — because from here on, losing
> the key store means losing the data.
>
> Until step 6, the plaintext column is still there. **That is your rollback.** It is the
> only one you get.

Watch for a while. Specifically watch for `MissingScope` from anything that reads or writes
without a tenant — background jobs and mix tasks are the usual offenders, and they will not
have shown up in your test suite.

## Step 6 — Contract

When you are sure, drop the plaintext column:

```elixir
defmodule MyApp.Repo.Migrations.ContractUserEmail do
  use Ecto.Migration

  def change do
    alter table(:users), do: remove(:legacy_email, :string)
  end
end
```

Remove `backfill_from: :legacy_email` and the `legacy_email` attribute from the resource in
the same deploy.

Then remember: every database backup taken before this migration still contains the
plaintext. Crypto-erasure cannot reach them, because those rows were never encrypted. If
making historical plaintext unrecoverable is the goal, age those backups out on a schedule
you actually enforce, and record the date after which backups contain only ciphertext.

## If something goes wrong

**The backfill says the field is not configured.**

```
MyApp.Accounts.User.email is not configured under `ash_vault`. Add `encrypt :email` to
the resource's `ash_vault` section. Known encrypted fields: [:ssn]
```

Step 2 has not been deployed, or the field name is wrong.

**The backfill has no source.**

```
no plaintext source for MyApp.Accounts.User.email. Pass `--from ATTR`, or declare
`encrypt :email, backfill_from: :legacy_email`.
```

**The provider is unreachable.** The run stops before the first batch, with
`ProviderUnavailable`. Nothing was written. Fix the provider and re-run; the task is
idempotent.

**Verification fails on some rows.** Those rows' ciphertext does not match their plaintext.
Do **not** contract. The plaintext is still authoritative — investigate which rows and why
(a concurrent write during the backfill is the usual answer, and a re-run will not fix them
because their encrypted column is no longer NULL). The blunt remedy is to null out the
encrypted column for the affected primary keys and re-run the backfill for them.

**A read after cut-over raises `MissingScope`.** Something is reading without a tenant. See
[Tenant-scoped encryption](tenant-scoped-encryption.md).

## Related

* [Operations](operations.md) — the full mix task reference and error taxonomy
* [Getting started](../tutorials/getting-started.md) — the greenfield path
* `AshVault.Backfill` — the engine, callable from a release without Mix
