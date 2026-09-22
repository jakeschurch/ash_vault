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
nonce, or the tag — fails with `AshVault.Errors.CiphertextIntegrityFailed`. AshVault never
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

`KeyDestroyed`, `KeyNotFound`, `ProviderUnavailable`, `CiphertextIntegrityFailed`,
`KeySizeMismatch` and `InvalidScope` are distinct errors. A provider outage never looks
like erasure; erasure never looks like an outage or like tampering; a configuration typo
is never reported as either. This matters when someone has to decide whether to page or to
close a ticket. See [Operations](operations.md) for the full taxonomy.

This is a **deliberate divergence** from `ash_cloak`, which recommends a generic
"decryption failed" so the error itself discloses nothing. The trade, the small disclosure
it accepts (erasure is observable to someone who can already read the ciphertext), why
AES-GCM means it is not a padding oracle, and the boundary responsibility it puts on any
public API built on AshVault are all written up in
`documentation/adr/0002-distinguishable-crypto-errors.md`. Read it before exposing these errors to
an end user.

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

### Sorting, ordering and prefix-matching encrypted values

The decrypt calculation is `filterable?: false, sortable?: false`, because randomized AEAD
ciphertext supports neither. This is not a limitation AshVault can configure away.

**Equality** matching is available, as an opt-in, through lookup tokens
(`encrypt :email, searchable?: true`) — at the cost of publishing the equality relation on
that column. See [Searchable fields](searchable-fields.md), and the residual-risk entry
below. Ordering and prefix matching remain impossible by construction, for every field,
searchable or not.

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

`AshVault.KeyProviders.OpenBao` uses `exportable: true` transit keys and exports raw key
material to the app; that is what lets the envelope stay self-contained and keeps all
wrapped key material out of the database. The consequence is that anything holding a
`transit/export` capability on those keys can read raw key material. The AshVault
application needs exactly that capability; nothing else should have it.

The residual risk is smaller than it sounds and larger than it looks. Smaller, because an
attacker who can call `transit/export` can almost always call `transit/decrypt` too —
having the key and being able to use the key are close to the same capability. Larger,
because an exported key *stays* in your process: it is a refcounted binary on some
process heap, the BEAM will not zero it, and it shows up in a crash dump, a core file, or
anything that reads `/proc/<pid>/mem`.

`AshVault.KeyProviders.OpenBaoTransit` is the answer to the second half, and is described
below.

## Choosing between the two OpenBao providers

AshVault ships two providers over the same OpenBao transit engine. They are not
"basic and advanced"; they trade different things, and most applications should use the
first one.

| | `AshVault.KeyProviders.OpenBao` | `AshVault.KeyProviders.OpenBaoTransit` |
|---|---|---|
| Where the AEAD runs | in your BEAM, `:crypto` | inside OpenBao |
| Raw DEK in process memory | yes, for the life of the call and beyond | **never** |
| Network cost per value (measured) | encrypt 3, **decrypt 2** | encrypt 3, **decrypt 3** |
| `AshVault.KeyProviders.Cached` helps | yes — both drop to **0** on a hit | no — it caches a key only when `is_binary/1`, so handles pass through uncached |
| Searchable fields (`searchable?: true`) | yes | **no**, and it is a compile-time error |
| Key size check at compile time | yes (`key_bytes/0`) | not applicable |
| Envelope | `aes_256_gcm_v1`, nonce + tag + ciphertext | `openbao_transit_v1`, transit's `vault:vN:` string verbatim |
| AAD binds scope, resource, field | yes | yes — `associated_data`, verified live |

### What the transit provider actually buys

Exactly one thing: the DEK never becomes an Elixir term. Not on a heap, not in a crash
dump, not in a core file, not readable by anything that can attach to the BEAM after the
fact. This is strictly stronger than the Rust NIF (`ash_vault_rustler`), which keeps key
material off the *BEAM* heap but still inside your process's address space.

It buys nothing else. It is not a defence against a compromised application process — an
attacker with code execution can call `transit/encrypt` and `transit/decrypt` with your
token exactly as the app does. What they cannot do is walk away with the key itself and
decrypt your database offline, later, without the token.

### What it costs, stated plainly

**Three HTTP round trips per encrypted value, on both read and write.** Per value, not
per query. These numbers are measured with a `[:finch, :request, :stop]` counter in
`test/ash_vault/ciphers/open_bao_transit_test.exs`, not estimated:

| | encrypt | decrypt |
|---|---|---|
| `AshVault.KeyProviders.OpenBaoTransit` | 3 | 3 |
| `AshVault.KeyProviders.OpenBao` | 3 | 2 |
| either, behind `AshVault.KeyProviders.Cached`, on a hit | 0 | 0 — *but see below* |

The three calls on a transit decrypt are: the scope's tombstone read, the
`transit/keys/<name>` metadata read (which is also where `exportable` is verified), and
`transit/decrypt`. Only the last one is the cipher's.

The caching row has an asterisk that matters. `AshVault.KeyProviders.Cached` caches a key
only when it `is_binary/1`, so a `AshVault.Key` handle passes straight through it,
uncached, on every single call. The handle is in principle cacheable — it is a
deterministic `{transit_key_name, version}` pair with no secret in it — but caching it
would also cache the tombstone decision that gates it, which is precisely the erasure-SLA
trade `AshVault.KeyProviders.Cached` documents at length. Today the wrapper simply does
nothing for this provider.

So the honest comparison is not "one call versus zero". It is: **with caching on, the
exporting provider costs 0 calls per value and this one costs 3.** Transit does have
batch endpoints (`transit/encrypt` accepts a `batch_input`), but the `AshVault.Cipher`
contract is one value at a time, so they go unused.

Budget it honestly: at a 1 ms round trip inside one datacenter, a 50-row page with two
encrypted columns is ~300 calls and ~300 ms of added latency, serialised, because
`AshVault.Calculations.Decrypt` reduces over values one at a time. If OpenBao is a
network hop away, it is worse. Measure before rolling it out beyond the fields that
genuinely need it — and note that "beyond the fields that need it" is expressible: point
one resource at a transit-backed vault and the rest at the exporting one, per
[Two vaults in one application](two-vaults.md).

### Choose the transit provider when

* the threat you are actually modelling is **key material recovered from process memory**
  — crash dumps shipped to a vendor, core files on a shared host, a hostile co-tenant on
  the same box, or a compliance regime that asks where the key was at rest *and in use*;
* the encrypted fields are few, read rarely, and never in a list view;
* you can afford the latency, and you have measured it rather than assumed it.

### Choose the exporting provider when

* you have searchable fields — the transit provider cannot serve a lookup key, by
  definition, and says so at compile time;
* encrypted fields appear in lists, exports, or anything that reads many rows;
* OpenBao is a network hop away rather than a sidecar;
* you are not certain which you need. It is the default for a reason.

### The OpenBao policy the transit provider needs

Verified against openbao 2.6.2: `POST /v1/transit/encrypt/<name>` **creates the key** if
it is absent, and pinning `key_version` does not prevent it. Withholding the `create`
capability on the encrypt path makes OpenBao refuse that with `403` while still allowing
encryption of existing keys:

```hcl
path "transit/keys/*"             { capabilities = ["read"] }
path "transit/keys/+/rotate"      { capabilities = ["update"] }
path "transit/keys/+/config"      { capabilities = ["update"] }
path "transit/encrypt/*"          { capabilities = ["update"] }
path "transit/decrypt/*"          { capabilities = ["update"] }
path "ashvault/data/tombstones/*" { capabilities = ["create", "read", "update"] }
```

There is deliberately **no** `transit/export/*` grant. Give key creation and destruction
to a separate, more privileged token.

Without that policy the guarantee still holds for reads, because `destroy/1` writes its
tombstone first and every read path checks it — but a write racing a `destroy/1` can
recreate the deleted transit key with fresh material. The recreated key is orphaned and
unreadable, not a resurrection; it is simply key material that should not exist.

### The one thing the transit provider checks that you cannot see

Creating a transit key that already exists is a silent no-op on OpenBao 2.6.2: the server
returns the existing metadata and ignores the `exportable` flag in your request. So
posting `exportable: false` proves nothing. `AshVault.KeyProviders.OpenBaoTransit` reads
`data.exportable` back on every metadata fetch and refuses with
`AshVault.Errors.ProviderUnavailable` if it is true, rather than quietly operating on
exportable key material while promising it does not exist.

This is also why the two providers use **different transit key names**
(`ashvault_<scope>` versus `ashvault_nx_<scope>`): sharing a name would mean whichever
provider touched a scope first silently decided whether its key is exportable. The
consequence is that they hold separate key material and separate tombstones for the same
scope, so erasing a subject with data under both means destroying under both vaults.

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

### AshVault's own telemetry, and what a handler can put back in

`AshVault.Telemetry` emits spans around every encrypt, decrypt, rotation and erasure. Their
metadata is held to the rule that nothing in it would matter if an APM recorded it
verbatim, because an APM will: no plaintext, no ciphertext, no key material, no actor
struct — only an `:actor_id`, a resource, a field, and for the key-lifecycle events a
scope. There is a test that deep-walks the emitted metadata and asserts none of the
forbidden values appear anywhere in it.

Two residuals:

* **The `:exception` event carries the raised error struct** in `:reason`, because that is
  `:telemetry.span/3`'s contract, not AshVault's choice. Those structs hold no plaintext,
  but they do hold a scope (a tenant id) and a provider-supplied reason. Treat an
  `:exception` handler as an exception reporter.
* **Your handler runs with your data in scope.** Nothing stops a handler enriching an
  audit row with the record it was called about. Do not.

The scope on the key-lifecycle events is a tenant identifier: not a secret, frequently
customer PII. An audit log built from these events survives the erasure it records — which
is the point of it — so it is one more place a destroyed subject's identifiers live on.
See [Operations](operations.md#telemetry-and-the-compliance-audit-log).

### Error messages are held to the same rule as ciphertext

Two error paths carry values that AshVault does not control, and both are redacted at
construction rather than at render time, because `inspect/1` on the struct reaches logs
just as readily as `Exception.message/1` does:

* `AshVault.Errors.SerializationFailed` carries the raw return of `Ash.Type.dump_to_embedded/3`
  or `cast_from_embedded/3`. Built-in Ash types return `:error` or `{:error, index: 0}`, but
  the `Ash.Type` contract permits `{:error, message: ..., value: value}` — where `value` is
  the plaintext. The shape and the keys survive; every leaf that is not an atom or an
  integer becomes `{:redacted, kind}`, `:message` included, since a type is free to
  interpolate the value into its message and truncating a short secret still yields the
  secret.
* `AshVault.Errors.MissingScope` describes the tenant it could not reduce to a scope key
  (`AshVault.Scopes.AshTenant.describe_tenant/1`) rather than inspecting it. A tenant is
  routinely a loaded record full of customer PII, and this error is raised precisely when
  something is already going wrong and being logged.

This closes the path AshVault controls. It does not close the general one — see *Plaintext
that escapes through other doors*, above.

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

### Lookup tokens leak equality within a scope, by construction

`encrypt :email, searchable?: true` stores a second, deterministic column:
`email_lookup = HMAC-SHA256(k, normalize(plaintext))`. It is opt-in per field, and turning
it on is a **deliberate disclosure**, not a neutral index.

What it gives away, and to whom:

* **Which rows share a value — to anyone with the database, with no key at all.** Two rows
  with the same token hold the same value. That is a deduplication oracle, a social graph
  and a re-identification vector, and it is visible in every historical backup you have
  ever taken. It is also precisely what makes the index work: you cannot have equality
  search without publishing the equality relation.
* **The frequency distribution**, to the same audience. The most common token in a
  `country` column is the most common country.
* **Confirmation of a guess, to an attacker who also holds the lookup key.** They compute
  `HMAC(k, "alice@example.com")` and look for it. They cannot *decrypt*: the lookup key is
  HKDF-separated from the data key, so the ability to search is strictly weaker than the
  ability to read, and a component that only needs to search can hold one without the
  other. But for a field with a small or enumerable domain — phone numbers, national IDs
  with checksums, dates of birth — "confirm a guess" is equivalent to "recover the value"
  by brute force. HMAC is fast on purpose; it is not a password hash and does not pretend
  to be.

**Low-cardinality fields are a bad fit and should be refused at design time.** A
`searchable?: true` boolean, a country code, a blood type, a gender or a coarse status is
an equality map of your whole table, and is close to not encrypting the column at all.

Two properties bound the damage, and both are enforced rather than merely intended:

1. **Lookup keys are per scope.** Equality never leaks *across* tenants: the same address
   in tenant A and tenant B produces two unrelated tokens, so a shared value never
   discloses a cross-customer relationship your customers did not agree to.
2. **The lookup key is never the encryption key, and never derived from it.** It comes
   from a separate provider callback (`c:AshVault.KeyProvider.lookup_key/1`), is **not**
   changed by `AshVault.rotate_key!/2`, and **is** destroyed by
   `AshVault.destroy_keys!/2` under the same tombstone — so crypto-erasure remains total,
   and a destroyed subject cannot have guesses confirmed about them afterwards.

The second property is also the failure mode worth naming: a lookup key derived from the
rotating data key would make every stored token stop matching the moment a scope rotated —
silently, with no error anywhere, with `unique?` quietly no longer preventing duplicates,
and with users unable to log in. `test/ash_vault/lookup_rotation_test.exs` is the
regression guard.

This is also why deterministic *encryption* is not the mechanism: it leaks the same
equality, destroys the AEAD guarantee (a fixed GCM nonce leaks the XOR of two messages and
the authentication subkey), and is reversible with the key, where an HMAC is one-way.

See [Searchable fields](searchable-fields.md).

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
`CiphertextIntegrityFailed`. This is a deliberate tradeoff — binding the resource is what stops
cross-resource relocation — but it means a module rename is a data migration. Re-encrypt
first, under the old module name, or keep the old name as the encrypted field's home.

## Related

* [Crypto-erasure](crypto-erasure.md) — the guarantee, in detail, with the checklist
* [Operations](operations.md) — the error taxonomy and how to respond to each
* `AshVault.Telemetry` — the audit events, and the rules on their metadata
* `documentation/adr/0001-no-cloak-vault.md` — why AshVault does not build on `Cloak.Vault`, and
  why a fixed AAD makes ciphertext freely relocatable
* `documentation/adr/0002-distinguishable-crypto-errors.md` — why §8 above diverges from
  `ash_cloak`'s generic-error advice, and what that costs
