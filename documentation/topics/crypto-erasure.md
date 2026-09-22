# Crypto-erasure

This is the feature AshVault exists for. One sentence:

> Customer data remains present in historical database backups, but destroying that
> customer's encryption keys makes the historical ciphertext permanently undecryptable.

Everything else in the library is in service of that sentence.

## The problem it solves

You receive a deletion request. You delete the rows. Six weeks later you restore last
month's backup to recover from an unrelated incident — and the deleted customer is back.
Not because anyone was careless: the backup is *supposed* to contain the state of the
database at that time, and that state included their data.

`DELETE` cannot reach backwards into a tarball. Neither can a retention policy, an audit
log, or a promise.

Encryption can, if and only if the keys live somewhere the restore does not reach. Then
"delete the data" becomes "destroy the key", the ciphertext in every historical backup
becomes 32 bytes of uniform noise per block, and the restore brings back rows nobody —
including you — can read.

## What destroying keys guarantees

`AshVault.destroy_keys!(vault, scope)` — or `mix ash_vault.destroy_keys` — asks the key
provider to destroy every key version for a scope and record a **tombstone**. After it
returns:

1. **Every value ever encrypted under that scope is unreadable.** Every encrypted field of
   every resource in that scope, in the live database and in every backup, snapshot, WAL
   archive, logical dump and stolen replica that already exists. There is no partial
   recovery: AES-256-GCM with a destroyed key is noise.
2. **Reads fail with a specific, distinguishable error.**
   `AshVault.Errors.KeyDestroyed`, from `Ash.read/2`, as a clean error value — not a
   raised exception, not a 500, and specifically **not**
   `AshVault.Errors.AuthenticationFailed`. Destruction is checked *before* any decryption
   is attempted, so erasure never looks like tampering.
3. **The scope cannot come back.** This is the tombstone's job, and it is the difference
   between crypto-erasure and silent data loss. See below.
4. **Restoring a database backup does not undo it.** The keys were never in the database.
   This is asserted end to end in `test/acceptance/backup_restore_test.exs`, against a
   real `pg_dump`/`psql` restore, twice: once with keys in OpenBao and once with keys in a
   `Local` root deliberately outside the backup. Step 8 of that test — rows present again,
   reads *still* `KeyDestroyed` — is the whole library.
5. **Erasure is per scope, per subject, not per table.** Destroying tenant A's key leaves
   tenant B entirely untouched, and B's rows keep decrypting, in the same tables, in the
   same restore.

## What it does not guarantee

Be precise about this with anyone you are making a deletion promise to.

**It does not erase plaintext that left AshVault.** Crypto-erasure erases what the
*ciphertext* held. Anything copied out before erasure is out of reach:

* logs, exception reports and APM traces that captured parameters or structs,
* analytics pipelines, data warehouses and CDC streams fed from the app layer,
* external integrations — email, billing, support tooling — that legitimately received
  plaintext,
* caches and search indexes built from decrypted values.

Inventory those paths *before* you promise deletion to anyone. AshVault scrubs plaintext
from `changeset.arguments` and `changeset.params`, and marks the backing attribute and the
action argument `sensitive?: true`, which covers the accidental-`inspect` case. It cannot
cover a pipeline you built on purpose.

**It does not erase metadata.** The row still exists. Row counts, row existence,
timestamps, foreign keys, and ciphertext length (which leaks plaintext length within a
block) are all still there. AshVault does not pad. An `encrypted_ssn` column is visibly
nine-ish bytes long in every backup. Where that matters, pad before encrypting.

**It does not erase the bytes from the media.** `AshVault.KeyProviders.Local` overwrites
each key file with random bytes before unlinking, and that is best-effort only. On
copy-on-write and log-structured filesystems — btrfs, ZFS, APFS, any SSD behind an FTL,
any snapshotted or thinly-provisioned volume — the overwrite is written *elsewhere* and
the original blocks survive until they are reclaimed, if ever. Treat the tombstone and the
AEAD as the mechanism that makes data unreadable, not the overwrite. If you need
media-level erasure, use full-disk encryption and destroy the volume key.

**It does not survive a key backup.** If you have a copy of the key store from before the
destroy, you can restore it and the data comes back. Your key-store retention window is
the real lifetime of a "destroyed" key. This is a genuine, sharp tradeoff with no free
answer:

* Keeping key backups makes erasure harder — every retained copy can resurrect a
  destroyed subject.
* Keeping no key backups makes data loss easy — losing the key store destroys every
  encrypted value in the database, permanently.

Decide which risk you are underwriting, write it down, and test the restore.

**It does not defend against a compromised application.** Plaintext exists in the BEAM
whenever a value is encrypted or decrypted, and an attacker with code execution can
request keys exactly as your app does. See the [threat model](threat-model.md).

## The tombstone, and why it must fail closed

Destroying key material leaves the scope **absent** in the provider. Absent is
indistinguishable from never-used. And `current_key/1` mints on first use.

So a provider that reads "no key here" and mints a fresh version 1 has *resurrected* the
erased subject. What follows is worse than not erasing at all:

* the subject looks brand new and starts writing rows under the new key,
* every pre-existing row carries `key_version: 1`, so `get_key(scope, 1)` returns the
  **new** v1 key,
* the tag check fails, and the operator is told `AshVault.Errors.AuthenticationFailed` —
  *your data was tampered with* — for an erasure the system performed on itself,
* and nothing anywhere records that a destroy was ever attempted.

Silent, total, undetectable data loss, reported as an attack.

A tombstone is a positive record that this scope was deliberately destroyed. Every
built-in provider checks it **first**, before touching key material, on `current_key/1`,
`get_key/2` and `rotate/1` alike, and returns `{:error, :destroyed}` forever.

The tombstone read **fails closed**. A read that cannot complete is never answered with
"not destroyed":

* `Local` uses `File.stat/1`, not `File.exists?/1` — the latter returns `false` for *any*
  failure (`:eacces` on a mode-000 parent, `:eio` on a failing disk, `:estale` on NFS,
  `:eloop`). Only a positive `:enoent` counts as absence; anything else is
  `ProviderUnavailable`.
* `Local` honours a tombstone on **presence alone** — its contents are never parsed to
  decide destruction, so a truncated or unreadable tombstone still means destroyed.
* `OpenBao` requires a positive identification of the response body in both directions:
  `200` means destroyed only with a map at `"data"`; `404` means absent only with an
  `"errors"` key holding an empty list. An HTML error page from an ingress mid-reload is
  `ProviderUnavailable`.
* `OpenBao` never creates the KV mount that holds tombstones on a **read** path. A
  missing mount answers `404 "no handler for route ..."`, status-identical to "no
  tombstone here"; mounting it and retrying would find an empty store and report every
  destroyed scope as intact. Mounting is an explicit operator step
  (`AshVault.KeyProviders.OpenBao.setup/0`). The tombstone *write* may still mount on
  demand — creating the store in order to record an erasure cannot lose one.
* `Local` never creates its own key root, for the same reason at the filesystem level: an
  unmounted key volume would otherwise be replaced by an empty directory with no
  tombstones in it. It requires an operator-created `.ash_vault_root` sentinel
  (`mix ash_vault.local.init`) and refuses to start without it.

### Ordering: tombstone first, then shred

`destroy/1` writes the tombstone **before** destroying key material, and fsyncs it. The
reverse order leaves a window — ENOSPC, EACCES, a read-only remount, a process crash — in
which the scope has no keys *and* no tombstone, which is exactly the resurrection scenario
above. Tombstone-first fails safe: the worst case is a scope marked destroyed whose key
files linger, and the provider refuses to serve them anyway.

`Local` rewrites the tombstone with a `shredded_at` once the shred completes, so an
interrupted destroy is visible to an operator.

### Writes racing a destroy

A write that arrives while a destroy is in flight does not get to store an unreadable
row. If the provider reports `{:error, :destroyed}` during the write's opportunistic
rotation, `AshVault.Vault.Runtime` raises `AshVault.Errors.KeyDestroyed` rather than
falling back to the pre-destroy key. A rejected write is recoverable; a "successful" write
storing ciphertext nobody can ever read is not.

## Running it

```
mix ash_vault.destroy_keys MyApp.Accounts.Organization --tenant acme
```

The task prints what is about to become undecryptable — every `resource.field` in the
project that encrypts with this vault under this scope — the current key version, and the
versions to be destroyed. Then:

```
ash_vault.destroy_keys=target resource=MyApp.Accounts.Organization tenant=acme scope=acme \
  vault=MyApp.Vault provider=AshVault.KeyProviders.OpenBao status=active version=3 versions=1,2,3 fields=4
undecryptable=MyApp.Accounts.User.email
undecryptable=MyApp.Accounts.User.ssn
undecryptable=MyApp.Accounts.Contact.phone
undecryptable=MyApp.Accounts.Organization.tax_id

!! IRREVERSIBLE CRYPTOGRAPHIC ERASURE !!
About to destroy every key version (1, 2, 3) for scope acme in MyApp.Vault.

4 field(s) across 3 resource(s) will become permanently undecryptable. This cannot be undone.

Type the scope back to confirm (acme):
```

`--yes` does **not** skip that prompt, and there is deliberately no `--force`: a deploy
script cannot destroy a tenant's data by passing one more flag. In `MIX_ENV=prod` the task
additionally refuses to run unless `MIX_ENV` was passed explicitly or
`--i-know-what-this-does` is given.

Afterwards the tombstone is re-read from the provider. If it does not answer
`{:error, :destroyed}`, the task exits non-zero rather than claiming an erasure that did
not happen:

```
The provider did not confirm a tombstone for scope acme.

It answered {:ok, %{...}} where `{:error, :destroyed}` was expected, so the
erasure cannot be reported as complete. Investigate AshVault.KeyProviders.OpenBao before
assuming this scope is erased.
```

On success:

```
ash_vault.destroy_keys=done scope=acme versions_destroyed=3 tombstone=confirmed
DESTROYED MyApp.Vault scope acme: 3 key version(s), 4 field(s) across 3 resource(s).
```

Destroying an already-destroyed scope prints `status=already_destroyed` and exits 0 —
there is nothing left to lose, so there is no prompt. Destroying a scope that was never
used exits non-zero: nothing has ever been encrypted under it, and asking to erase it
probably means the scope key is wrong.

From code, without Mix:

```elixir
:ok = AshVault.destroy_keys!(MyApp.Vault, "acme")
```

Or as a generic action on the resource that owns the scope, so it runs through ordinary
Ash policies and actors:

```elixir
ash_vault do
  vault MyApp.Vault
  scope_owner? true

  key_lifecycle do
    rotate :rotate_key
    destroy :destroy_keys
  end
end
```

```elixir
MyApp.Accounts.Organization
|> Ash.ActionInput.for_action(:destroy_keys, %{}, tenant: org, actor: admin)
|> Ash.run_action!()
```

`key_lifecycle` is only permitted on a `scope_owner? true` resource. Rotation and erasure
act on a whole key scope, so they belong on the resource that *owns* the scope — your
tenant or organization — not on every resource that happens to have encrypted fields. The
verifier says so:

```
`key_lifecycle` requires `scope_owner? true`.

Key rotation and cryptographic erasure act on a whole key scope, so they belong on
the resource that *owns* the scope — your tenant or organization — not on every
resource that happens to have encrypted fields.
```

## Operational checklist

Before you rely on this in production:

- [ ] **The key store is a different system from the database.** Not a different schema,
      not a different table, not a different database on the same server that one
      `pg_dumpall` covers. A different system, with its own credentials.
- [ ] **The key store is excluded from the database backup job**, explicitly, and is not
      on a volume you snapshot with the database. If one restore brings back both, the
      central promise is void.
- [ ] **The key store has its own backup and its own retention policy**, written down, with
      the erasure-versus-loss tradeoff stated. Test that restore.
- [ ] **You have run the equivalent of `test/acceptance/backup_restore_test.exs` against
      your own deployment**: write, back up, destroy, restore, confirm the restored rows
      still read `KeyDestroyed` and another scope still decrypts.
- [ ] **For `Local`:** the root is initialised with `mix ash_vault.local.init`, the
      sentinel is present, the mode is `0700`, and it is a mount point that is actually
      mounted at boot. Confirm the provider *refuses to start* when it is not — that
      refusal is the safety mechanism, not an inconvenience.
- [ ] **For `OpenBao`:** the KV mount exists (`AshVault.KeyProviders.OpenBao.setup/0`), the
      app's token has transit *and* the `transit/export` capability, and nothing else does.
- [ ] **Your monitoring distinguishes `KeyDestroyed` from `ProviderUnavailable` from
      `AuthenticationFailed`.** They mean close the ticket, page someone, and investigate
      an attack, respectively. See [Operations](operations.md).
- [ ] **You have inventoried every path plaintext takes out of the application** — logs,
      warehouse, CDC, integrations, caches, search — and either stopped them or included
      them in the deletion runbook.
- [ ] **Your deletion runbook records which scope was destroyed and when.** The tombstone
      is the provider's record; you want one of your own too, because
      `mix ash_vault.key_info` tells you a scope is destroyed but not who asked.
- [ ] **No key cache is in play.** v1 has none, so keys are not resident between
      operations. If you ever add one, it must be evicted synchronously *before*
      `destroy_keys!/2` returns, or erasure is a lie for the length of the TTL.

## Related

* [Threat model](threat-model.md) — what this does and does not defend against
* [Rotation](rotation.md) — rotation is not erasure, and does not make data unreadable
* [Operations](operations.md) — the mix tasks and the error taxonomy
* [Writing a key provider](../how-to/writing-a-key-provider.md) — if you implement the
  tombstone yourself
