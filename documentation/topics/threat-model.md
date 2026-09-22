# Threat model

AshVault encrypts individual Ash attributes with a key that belongs to a **scope** (by
default, the Ash tenant). The key material lives in an external key provider. This document
states precisely what that does and does not buy you.

Read the non-goals. They are not a disclaimer; they are half the design.

## The property we are actually buying

> Customer data remains present in historical database backups, but destroying that
> customer's encryption keys makes the historical ciphertext permanently undecryptable.

Everything below is in service of that sentence.

## In scope — attacks AshVault defends against

### 1. Historical PostgreSQL backups, snapshots, and logical dumps

Encrypted columns contain only an AshVault envelope: magic, envelope version, cipher id,
key version, nonce, auth tag, ciphertext. No key material, no wrapped key, no plaintext. A
`pg_dump`, a filesystem snapshot, a WAL archive, or a stolen replica yields ciphertext
only.

There is no plaintext column to forget about, either: the transformer *removes* the
attribute entity, so no data layer can write one.

### 2. Accidental restoration after a deletion request

This is the motivating case. Because the key store is a separate system, restoring an old
database does not restore keys. The provider keeps a **tombstone** for a destroyed scope,
so a destroyed scope cannot be silently re-created by a later write — reads return
`AshVault.Errors.KeyDestroyed`, not a generic failure, and not fresh usable ciphertext.

### 3. Database compromise without key-provider compromise

An attacker with full read access to PostgreSQL — including `pg_dump`, replication, or a
leaked snapshot — obtains no plaintext. Breaking one tenant's data requires the key
provider.

### 4. Ciphertext moved between tenants

AEAD additional authenticated data binds every ciphertext to its scope. Pasting tenant A's
`encrypted_email` into tenant B's row fails authentication, and the two tenants use
different keys besides.

### 5. Ciphertext moved between resources or fields

The same AAD binds resource module and field name:
`"ashvault:v1|<scope>|<Resource>|<field>"`. Copying `users.encrypted_ssn` into
`users.encrypted_email`, or into `contacts.encrypted_phone`, fails authentication rather
than silently decrypting into the wrong field.

### 6. Tampered ciphertext

AES-256-GCM authenticates the ciphertext. Any modified byte — in the ciphertext, the
nonce, or the tag — fails with `AshVault.Errors.AuthenticationFailed`. AshVault never
returns partially-decrypted or unauthenticated data.

This includes a **truncated tag**, which is a real attack and not an edge case: OTP's
`:crypto.crypto_one_time_aead/7` accepts 1-, 2-, 4-, 8- and 12-byte GCM tags and compares
only their leading bytes, and the envelope carries `tag_len` as a byte read straight from
the database. GCM is CTR mode, so an attacker with database *write* access could XOR the
ciphertext to any chosen plaintext, store `tag_len: 1`, and forge successfully within 256
read attempts. `AshVault.Ciphers.AES.GCM.decrypt/3` therefore requires exactly a 16-byte
tag and a 12-byte nonce before the key reaches `:crypto`, which restores the 2^-128
forgery bound.

### 7. Key rotation without re-encryption

Each envelope carries the key version that produced it, so rotating a scope's key changes
what new writes use without touching, or endangering, existing rows.

### 8. Operational distinguishability

`KeyDestroyed`, `KeyNotFound`, `ProviderUnavailable`, `AuthenticationFailed`,
`KeySizeMismatch` and `InvalidScope` are distinct errors. A provider outage never looks
like erasure; erasure never looks like an outage or like tampering; a configuration typo
is never reported as either. This matters when someone has to decide whether to page or to
close a ticket. See [Operations](operations.md) for the full taxonomy.

### 9. Unstable identifiers silently relocating key material

Scope keys are binaries derived by stringification, never
`:erlang.term_to_binary/1`, and the AAD format is a frozen, human-inspectable string for
the same reason. The external term format is not guaranteed stable across OTP releases;
an encoding change would relocate a tenant's tombstone (resurrecting the scope with a
fresh key) and its key name (making every existing ciphertext unreadable) in one upgrade.
`AshVault.Vault.Runtime` rejects a non-binary scope with `AshVault.Errors.InvalidScope`,
and every provider rejects one with an `ArgumentError`.

### 10. Untrusted bytes in the decode path

`AshVault.Envelope.decode/1` is total: any binary — truncated, foreign, empty — produces a
tagged error rather than an exception, with no atom interning, no decompression and no
length-driven allocation. The plaintext decoder additionally refuses a compressed external
term (`<<131, 80, ...>>`) outright, because `:safe` does not stop a decompression bomb, and
goes through Ash's `non_executable_binary_to_term/2` helper with `:safe`, which blocks
atom interning and funs/refs/ports.

## Out of scope — non-goals

AshVault does **not** defend against these, and no configuration of it will.

### A compromised application process

Plaintext exists in the BEAM's memory whenever a value is encrypted or decrypted. An
attacker with code execution in your app, a remote console, or the ability to attach
`:observer` can read plaintext and can request keys from the provider exactly as the app
does.

### An attacker controlling both the app and the provider

If the same credential or the same host grants both, there is no separation left to
exploit. The provider token is the crown jewel; treat it as such.

### Plaintext that escapes through other doors

* logs, exception reports, and APM traces that capture parameters or structs
* analytics pipelines, data warehouses, and CDC streams fed from the app layer
* external integrations (email, billing, support tooling) that receive plaintext
  legitimately
* caches and search indexes built from decrypted values

Crypto-erasure only erases what the ciphertext held. Everything copied out of AshVault
before erasure is out of its reach — inventory those paths before you promise deletion to
anyone.

### Endpoint and client compromise

A compromised browser, laptop, or operator account sees whatever that user is authorized
to see.

### Traffic analysis and metadata

Row counts, row existence, timestamps, ciphertext length (which leaks plaintext length
within a block), and access patterns are not hidden. AshVault does not pad.

### Authorization

AshVault performs no authorization. `Ash.Policy.Authorizer` and field policies decide who
may read or write; AshVault assumes any operation that reaches it was already authorized.
Adding a second, crypto-layer authorization check would create two sources of truth that
drift.

One constraint comes with that: field policies must use **filter or simple checks only**.
Anything else raises `Ash.Error.Forbidden` with "Field policies must currently use only
filter checks or simple checks". A denied field arrives at the decrypt calculation as
`%Ash.ForbiddenField{}` and is passed through untouched — not decrypted, and not turned
into an error.

### Searching, sorting and filtering on encrypted values

The decrypt calculation is `filterable?: false, sortable?: false`, because randomized AEAD
ciphertext supports neither. This is not a limitation AshVault can configure away; see
[Searchable fields](searchable-fields.md) for the design that would address it, and its own
disclosure tradeoff.

## Residual risks worth writing down

These are known, accepted, and in some cases unfixable. They are here because dropping
them quietly would be the dishonest thing to do.

### The OpenBao token is in the `x-vault-token` header, and telemetry can record it

AshVault never logs the token, never puts it in an error struct, and never puts it in an
exception message — the transport failures it reports carry only the exception *kind* and
reason, never the request.

It cannot promise more than that. The token is sent as the `x-vault-token` header, so the
raw value necessarily sits in the `Req.Request` and `Finch.Request` structs for the life of
the call. `Req`'s own `Inspect` implementation redacts only `authorization`, and Finch's
`[:finch, :request, :start | :stop | :exception]` telemetry metadata carries the request
headers verbatim — which APM handlers routinely record. **If you attach handlers to those
events, filter `x-vault-token` out of the metadata yourself.** Nothing inside AshVault can
do it for you.

This is documented rather than fixed because the fix is not AshVault's to make.

### Exportable transit keys

The OpenBao provider uses `exportable: true` transit keys and exports raw key material to
the app; that is what lets the envelope stay self-contained and keeps all wrapped key
material out of the database. The consequence is that anything holding a
`transit/export` capability on those keys can read raw key material. The AshVault
application needs exactly that capability; nothing else should have it.

A non-exporting provider that round-trips each value through OpenBao is possible but
changes the `AshVault.KeyProvider` contract (no raw key), so it is not in v1.

### Overwrite-before-unlink guarantees nothing about the media

`AshVault.KeyProviders.Local` overwrites key files with random bytes before unlinking, and
that is best-effort only. On copy-on-write and log-structured filesystems (btrfs, ZFS,
APFS, any SSD behind an FTL, any snapshotted or thinly-provisioned volume) the overwrite
lands elsewhere and the original blocks survive until reclaimed, if ever. The tombstone and
the AEAD are the mechanism that makes data unreadable, not the overwrite.

### Directory fsync is impossible in OTP

`Local` fsyncs every key file and every `meta.json` before renaming it into place, but OTP
offers no way to open a directory for `:file.sync/1` (`:file.open/2` on a directory returns
`{:error, :eisdir}`), so the containing directory is never fsynced. Durability of the
*directory entry* is left to the filesystem's own ordering guarantees. The load-bearing
property — a key file durably written before the metadata that names it — does not depend
on it.

### Key backups versus erasure

There is no free answer here. Retained copies of the key store can resurrect a destroyed
subject, so your key-backup retention window is the real lifetime of a "destroyed" key; no
copies at all means losing the key store destroys every encrypted value permanently.
State which risk you are underwriting and test the restore.

### Key caching

v1 has **no** key cache, so keys are not resident between operations. Any future
`AshVault.KeyCache` must be in-memory only, TTL-bounded, and evicted **synchronously
before** `AshVault.destroy_keys!/2` returns — otherwise erasure is a lie for the length of
the TTL. `AshVault.Vault.Runtime.destroy!/2` carries a commented call site marking where
that eviction goes.

### Lookup tokens (post-v1)

Searchable fields, when they land, will leak equality within a scope by construction. That
is the point of them, and it is a real disclosure: an attacker with the database learns
which rows share a value, and can confirm a guessed value if they also hold the lookup
key. Lookup keys must be per-scope so equality never leaks across tenants. See
[Searchable fields](searchable-fields.md).

### Length leakage

`encrypted_ssn` is nine-ish bytes long, and visibly so, in every backup. Where that
matters, pad before encrypting.

### Erasure is per scope, not per row

Destroying a tenant's key erases every encrypted field of every resource in that tenant. If
you need row-level erasure, the scope must be row-level — that is what the pluggable
`AshVault.Scope` behaviour is for, at the cost of one provider key per row. See
[Writing a scope](../how-to/writing-a-scope.md).

### Renaming a resource invalidates its ciphertext

The AAD contains `inspect(resource)`. Renaming `MyApp.User` to `MyApp.Accounts.User`
changes the AAD, and every existing row of that resource then fails with
`AuthenticationFailed`. This is a deliberate tradeoff — binding the resource is what stops
cross-resource relocation — but it means a module rename is a data migration. Re-encrypt
first, under the old module name, or keep the old name as the encrypted field's home.

## Related

* [Crypto-erasure](crypto-erasure.md) — the guarantee, in detail, with the checklist
* [Operations](operations.md) — the error taxonomy and how to respond to each
* `docs/adr/0001-no-cloak-vault.md` — why AshVault does not build on `Cloak.Vault`, and
  why a fixed AAD makes ciphertext freely relocatable
