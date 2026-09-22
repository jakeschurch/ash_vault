# Searchable fields

> #### Not implemented in v1 {: .error}
>
> `searchable?` and `unique?` exist in the DSL schema but are **rejected at compile time**.
> This page documents the design so you can plan around it, and states the disclosure
> tradeoff honestly so you can decide whether you want it at all.

## What you can and cannot do today

You cannot filter, sort, match or join on an encrypted field. The generated decrypt
calculation is declared `filterable?: false, sortable?: false`, because randomized AEAD
ciphertext supports neither: the same plaintext encrypted twice produces two completely
different blobs (fresh 12-byte nonce every time), so `WHERE encrypted_email = $1` matches
nothing and `ORDER BY encrypted_email` orders by noise.

That is not a configuration AshVault withholds. It is what the encryption *is*.

If you write this:

```elixir
ash_vault do
  vault MyApp.Vault
  encrypt :email, searchable?: true
end
```

the resource does not compile:

```
`searchable?` and `unique?` are not implemented in v1 (on :email). Remove them;
lookup tokens are post-v1.
```

(raised as a `Spark.Error.DslError` at `[:ash_vault, :encrypt]`, from
`AshVault.Transformers.SetupEncryption`). `unique?: true` gets the same message. They are
rejected rather than silently ignored, so nobody ships believing they have a feature they
do not have.

### What to do instead, today

* **Look up by an identifier you do not encrypt.** An email is often both a credential and
  a lookup key; a `user_id`, an opaque login token, or a separate non-sensitive
  `email_domain` column can carry the lookup while the value stays encrypted.
* **Filter on something else and decrypt in the application.** `Ash.read` a bounded set by
  tenant/date/status, load the field, and filter in Elixir. This is fine for tens or
  hundreds of rows per request and terrible for millions.
* **Keep a deliberately non-sensitive projection.** Last four digits of a card, a
  domain, a coarse bucket. You are choosing exactly what to disclose, in the open,
  which is a much easier thing to reason about than a token scheme.
* **Reconsider whether the field needs to be searchable.** In practice a surprising number
  of "we need to search on it" requirements are really "support needs to confirm a value
  the customer just read out", which an equality check on a value you already have
  satisfies — and which is what lookup tokens would give you.

## The design: per-scope HMAC lookup tokens

The intended mechanism, when it lands, is a second column holding a keyed hash.

For `encrypt :email, searchable?: true`, the transformer would add an `email_lookup`
`:binary` attribute alongside `encrypted_email`, and the encrypt change would write both:

```
email_lookup = HMAC-SHA256(lookup_key(scope), normalize(plaintext))
```

The lookup key is **derived from the scope's encryption key by HKDF with a distinct info
string**, so it is never the encryption key itself:

```
lookup_key(scope) = HKDF-Expand(scope_key, info: "ashvault:v1:lookup", length: 32)
```

That derivation is the load-bearing part. A separate key for lookup means:

* a component that only needs to *search* (a lookup service, a read replica of the search
  index) can hold the lookup key without being able to decrypt anything;
* an HMAC key leak does not compromise confidentiality of the values, only equality;
* and, critically, **destroying the scope's key destroys the lookup key too**, because the
  lookup key is derived from it and stored nowhere. Crypto-erasure still works: the
  tokens become unguessable-but-useless, and nothing can regenerate them.

`unique?: true` would additionally add a unique identity on `(scope, email_lookup)`, which
gives you database-enforced uniqueness on a value the database cannot read.

### Why HMAC, and not deterministic encryption

Deterministic encryption — encrypting with a fixed nonce so equal plaintexts produce equal
ciphertexts — is the obvious shortcut and is explicitly **not** the mechanism.

* It destroys the AEAD guarantee. A fixed nonce under GCM is catastrophic: two messages
  under the same key and nonce leak their XOR and the authentication subkey, allowing
  forgery.
* It conflates two keys into one. The value that can be *searched* and the value that can
  be *decrypted* would be the same ciphertext, so anything able to search can decrypt.
* It makes the leak permanent and total: the stored value is simultaneously the index and
  the secret.

A separate HMAC token keeps the encrypted column randomized (and therefore properly
authenticated) and confines the equality leak to a column that holds nothing else.

### Normalization is part of the security boundary

`normalize/1` has to be pinned down and versioned, because it decides what "equal" means.
Case-folding an email so `A@B.com` matches `a@b.com` is convenient and also narrows the
guessing space. Changing normalization later invalidates every token in the database —
it is a data migration, not a tweak. Expect the eventual implementation to bind the
normalization version into the HMAC info string for exactly that reason.

## The equality-leakage tradeoff, stated plainly

A lookup token column is a **deliberate disclosure**, not a neutral index. Anyone with the
database — including every historical backup — learns:

* **which rows share a value.** Two users with the same token have the same email. That is
  a social graph, a deduplication oracle, and a re-identification vector, and it is visible
  without any key at all.
* **the frequency distribution.** The most common token in a `country` column is the
  most common country. Low-entropy fields leak almost completely to frequency analysis:
  a token on a `blood_type`, a `gender`, a `zip_code` or a boolean-ish field is close to
  storing it in plaintext.
* **confirmation of a guess, if they also hold the lookup key.** With the key, an attacker
  computes `HMAC(key, "alice@example.com")` and checks for its presence. For a field with a
  small or enumerable domain — phone numbers, national IDs with checksums, dates of birth —
  "confirm a guess" is equivalent to "recover the value" by brute force. HMAC is fast on
  purpose; it is not a password hash and does not pretend to be.

Two constraints follow, and both are non-negotiable in the design:

1. **Lookup keys must be per-scope**, so equality never leaks *across* tenants. A global
   lookup key would let anyone with the database determine that a user of tenant A and a
   user of tenant B share an email — a cross-customer disclosure your customers did not
   agree to.
2. **The lookup key must never be the encryption key**, so that holding the ability to
   search is strictly weaker than holding the ability to read.

The honest summary: lookup tokens buy you equality search at the cost of publishing the
equality relation on that column, forever, into every backup you have ever taken. For a
high-entropy field where you only need "does this exact value already exist", that is
usually a good trade. For a low-cardinality field it is close to not encrypting at all.
Decide per column, not per application.

## Related

* [Threat model](threat-model.md) — the residual-risk entry for lookup tokens
* [Architecture](architecture.md) — why the ciphertext is randomized in the first place
* [Crypto-erasure](crypto-erasure.md) — why deriving the lookup key from the scope key is
  what keeps erasure total
