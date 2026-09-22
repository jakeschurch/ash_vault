# Searchable encrypted fields — implementation spec

Supersedes the design sketch in `documentation/topics/searchable-fields.md` where they differ.
That page describes the concept; this one is what to build.

## The problem

AES-GCM uses a fresh random nonce per write, so the same plaintext encrypts to different bytes
every time. `WHERE encrypted_email = ?` never matches and a unique index on the column is
meaningless. Login-by-email, "is this address taken", and dedupe are all impossible today.

## The mechanism

A second, deterministic column beside the ciphertext:

    plaintext
      ├── AES-GCM → encrypted_email   (randomized, unsearchable)
      └── HMAC    → email_lookup      (deterministic, indexable)

Query and constrain on `email_lookup`; decrypt `encrypted_email` only after finding the row.

## THE TRAP — read this before writing any code

**The lookup key MUST NOT be the rotating DEK, and MUST NOT be derived from it.**

If the lookup token is derived from the current encryption key, then `rotate_key!/2` changes
every future token while every stored token still reflects the old key. Lookups for existing
rows silently stop matching. Nothing errors. `unique?` stops preventing duplicates. Users
cannot log in. This is a catastrophic, silent failure and it would pass every test that only
checks "write then immediately read".

Therefore:

- The provider grows an optional callback:

      @callback lookup_key(scope()) :: {:ok, binary()} | {:error, term()}
      @optional_callbacks lookup_key: 1

- It returns a **stable, non-rotating, per-scope** secret. `rotate/1` MUST NOT change it.
  `destroy/1` MUST destroy it along with everything else — erasure still erases.
- A provider that does not implement it makes `searchable?: true` a compile-time DSL error
  naming the provider, not a runtime surprise.
- Implement for all three providers. Memory: a second map. Local: a `lookup.key` file beside
  the versioned keys, same crash-safe write ordering, same tombstone gate. OpenBao: a separate
  non-rotating transit key (suffix the name, e.g. `<key_name>_lookup`), also `exportable`, also
  deleted by `destroy/1` and gated by the same tombstone.

Per-field separation comes from HKDF, not from separate provider keys:

    lookup_key_for_field =
      HKDF-SHA256(ikm: provider_lookup_key(scope),
                  info: "ash_vault:lookup:v1|" <> inspect(resource) <> "|" <> to_string(field))

    token = HMAC-SHA256(lookup_key_for_field, normalized_plaintext)

Use `:crypto.mac(:hmac, :sha256, key, data)`. HKDF is not in OTP — implement extract/expand
directly from RFC 5869 with `:crypto.mac/4`, in about fifteen lines, and unit-test it against
the RFC 5869 test vectors. Do not hand-roll anything else.

**Rotating a lookup key is a backfill, not a rotation.** Document that plainly, and make
`AshVault.rotate_key!/2`'s docs say it does not touch lookup tokens.

## Normalization

`normalize:` option per field: `:none` (default), `:downcase`, `:downcase_trim`, or an MFA/fun.

Default `:none` deliberately — silent normalization changes equality semantics, and for an
email field the user should opt in knowingly. Document loudly that **changing `normalize:`
after rows exist invalidates every stored token** and requires a backfill, exactly like
changing a hash function.

Normalization applies to a binary. For a non-binary field, `searchable?: true` is a DSL error
unless a custom MFA is given — do not silently `to_string/1` a struct.

## DSL and generated schema

```elixir
ash_vault do
  vault MyApp.Vault
  encrypt :email, searchable?: true, unique?: true, normalize: :downcase_trim
end
```

Generates, in addition to the existing `encrypted_email` + `email` calculation:

- attribute `:email_lookup`, type `:binary`, `public?: false`, `sensitive?: true`,
  `allow_nil?: true` (nil plaintext produces no token), `filterable?: true`, `select_by_default?: false`
- when `unique?: true`, an `Ash.Resource.Info` identity on `[:email_lookup]` — plus the
  tenant attribute when the resource uses attribute multitenancy, so uniqueness is per tenant.
  Name it `:email_lookup_unique`. Check `Ash.Resource.Builder.add_identity/4` and whether
  `all_tenants?` is the right knob for the context strategy.
- `unique?: true` without `searchable?: true` is a DSL error explaining uniqueness needs a token.

Write path: the same `before_action` hook that encrypts also computes and
`force_change_attribute`s the token. Nil plaintext → nil token. The token must be computed from
the **same normalized value** that gets encrypted, and both must be scrubbed from params.

## Querying — the part that must be pleasant

Users must never build a token by hand. Provide:

```elixir
AshVault.Query.filter_by(Resource, :email, "Jake@Example.com", scope_or_context)
# -> an Ash.Query filtered on email_lookup
```

and generate a read action per searchable field, `:by_<field>`, taking the plaintext as an
argument, so `MyApp.Accounts.get_user_by_email!("jake@example.com")` works through an ordinary
code interface. The action's argument must be `sensitive?: true`.

The scope must resolve the same way a write does — through the configured `AshVault.Scope`,
from the query's tenant — so a query without a tenant raises `MissingScope` exactly as a write
would, rather than returning zero rows. **Returning an empty result for a missing tenant would
be the worst outcome here**: it looks like "no such user" and would sail through review.

## Migration

`mix ash_vault.backfill` must learn `--lookup` to populate tokens for existing encrypted rows:
read, decrypt, compute token, write only the lookup column. Same batching, resumability
(filter on lookup-is-null) and idempotence as the existing engine.

## Threat model additions — write these, do not soften

- A deterministic token leaks **equality within a scope**: anyone with database access sees
  which rows share a value, with no key at all. That is what makes the index work.
- Per-scope keys keep that leakage inside one tenant instead of across all of them.
- An attacker holding the lookup key can **confirm guesses** (compute the token for a candidate
  email and look for it) but cannot decrypt — the lookup key is HKDF-separated from the DEK.
- Low-cardinality fields are a bad fit: a `searchable?: true` boolean or a country code is an
  equality map of your whole table. Say so.
- This is why deterministic *encryption* is not the mechanism: it leaks the same equality and
  is reversible with the key, where an HMAC is one-way.

## Tests

- RFC 5869 HKDF vectors.
- Token stability: same plaintext + same scope → same token across processes and restarts.
- Token separation: same plaintext, different field → different token; different scope →
  different token; different resource → different token.
- **Rotation does not change tokens.** Encrypt, rotate, encrypt again, assert both rows'
  tokens match a fresh lookup. This is the regression guard for the trap above.
- `destroy_keys!` destroys the lookup key too: after erasure, `filter_by` raises `KeyDestroyed`
  rather than returning zero rows.
- `unique?` actually rejects a duplicate, and permits the same value in a different tenant.
- Missing tenant raises `MissingScope`, never an empty result.
- Nil plaintext → nil token, and does not trip `unique?` for multiple nil rows.
- Normalization: `:downcase_trim` matches `" Jake@Example.COM "`; `:none` does not.
- Postgres integration: the lookup column is indexed and a query uses it (assert via `EXPLAIN`
  that it is not a sequential scan).
- Backfill `--lookup` populates tokens and is idempotent on a second run.
