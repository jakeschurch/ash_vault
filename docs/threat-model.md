# AshVault threat model

AshVault encrypts individual Ash attributes with a key that belongs to a **scope**
(by default, the Ash tenant). The key material lives in an external key provider.
This document states precisely what that does and does not buy you.

## The property we are actually buying

> Customer data remains present in historical database backups, but destroying that
> customer's encryption keys makes the historical ciphertext permanently undecryptable.

Everything below is in service of that sentence.

## In scope — attacks AshVault defends against

### 1. Historical PostgreSQL backups, snapshots, and logical dumps

Encrypted columns contain only an `AshVault` envelope: magic, envelope version, cipher id,
key version, nonce, auth tag, ciphertext. No key material, no wrapped key, no plaintext.
A `pg_dump`, a filesystem snapshot, a WAL archive, or a stolen replica yields ciphertext only.

### 2. Accidental restoration after a deletion request

This is the motivating case. Because the key store is a separate system, restoring an old
database does not restore keys. The provider keeps a **tombstone** for a destroyed scope, so
a destroyed scope cannot be silently re-created by a later write — reads return
`AshVault.Errors.KeyDestroyed`, not a generic failure, and not fresh usable ciphertext.

### 3. Database compromise without key-provider compromise

An attacker with full read access to PostgreSQL — including `pg_dump`, replication, or a
leaked snapshot — obtains no plaintext. Breaking one tenant's data requires the key provider.

### 4. Ciphertext moved between tenants

AEAD additional authenticated data binds every ciphertext to its scope. Pasting tenant A's
`encrypted_email` into tenant B's row fails authentication, and the two tenants use different
keys besides.

### 5. Ciphertext moved between resources or fields

The same AAD binds resource module and field name:
`"ashvault:v1|<scope>|<Resource>|<field>"`. Copying `users.encrypted_ssn` into
`users.encrypted_email`, or into `contacts.encrypted_phone`, fails authentication rather
than silently decrypting into the wrong field.

### 6. Tampered ciphertext

AES-256-GCM authenticates the ciphertext. Any modified byte — in the ciphertext, the nonce,
or the tag — fails with `AshVault.Errors.AuthenticationFailed`. AshVault never returns
partially-decrypted or unauthenticated data.

### 7. Key rotation without re-encryption

Each envelope carries the key version that produced it, so rotating a scope's key changes
what new writes use without touching, or endangering, existing rows.

### 8. Operational distinguishability

`KeyDestroyed`, `KeyNotFound`, `ProviderUnavailable`, and `AuthenticationFailed` are distinct
errors. A provider outage never looks like erasure; erasure never looks like an outage or like
tampering. This matters when someone has to decide whether to page or to close a ticket.

## Out of scope — non-goals

AshVault does **not** defend against these, and no configuration of it will.

### A compromised application process

Plaintext exists in the BEAM's memory whenever a value is encrypted or decrypted. An attacker
with code execution in your app, a remote console, or the ability to attach `:observer` can
read plaintext and can request keys from the provider exactly as the app does.

### An attacker controlling both the app and the provider

If the same credential or the same host grants both, there is no separation left to exploit.
The provider token is the crown jewel; treat it as such.

### Plaintext that escapes through other doors

- logs, exception reports, and APM traces that capture parameters or structs
- analytics pipelines, data warehouses, and CDC streams fed from the app layer
- external integrations (email, billing, support tooling) that receive plaintext legitimately
- caches and search indexes built from decrypted values

Crypto-erasure only erases what the ciphertext held. Everything copied out of AshVault before
erasure is out of its reach — inventory those paths before you promise deletion to anyone.

### Endpoint and client compromise

A compromised browser, laptop, or operator account sees whatever that user is authorized to see.

### Traffic analysis and metadata

Row counts, row existence, timestamps, ciphertext length (which leaks plaintext length within
a block), and access patterns are not hidden. AshVault does not pad.

### Authorization

AshVault performs no authorization. `Ash.Policy.Authorizer` and field policies decide who may
read or write; AshVault assumes any operation that reaches it was already authorized. Adding a
second, crypto-layer authorization check would create two sources of truth that drift.

## Residual risks worth writing down

- **Exportable transit keys.** The OpenBao provider exports raw key material to the app. The
  export capability must be scoped to the app's token and nothing else. A non-exporting
  provider that round-trips each value through OpenBao is possible but changes the
  `KeyProvider` contract; it is not in v1.
- **Key caching.** v1 has no key cache, so keys are not resident between operations. Any
  future `AshVault.KeyCache` must be in-memory only, TTL-bounded, and evicted synchronously
  before `destroy_keys!/2` returns — otherwise erasure is a lie for the length of the TTL.
- **Lookup tokens.** Searchable fields (HMAC lookup tokens) leak equality within a scope by
  construction. That is the point of them, and it is a real disclosure: an attacker with the
  database learns which rows share a value, and can confirm a guessed value only if they also
  hold the lookup key. Lookup keys must be per-scope so equality never leaks across tenants.
- **Length leakage.** `encrypted_ssn` is nine-ish bytes long. Where that matters, pad before
  encrypting.
- **Erasure is per scope, not per row.** Destroying a tenant's key erases every encrypted
  field of every resource in that tenant. If you need row-level erasure, the scope must be
  row-level — that is what the pluggable `AshVault.Scope` behaviour is for, at the cost of one
  provider key per row.
