# Searchable fields

You cannot sort, order or prefix-match an encrypted field. You *can* match it for
**equality**, by opting a field into a second, deterministic column beside its ciphertext:

```elixir
ash_vault do
  vault MyApp.Vault

  encrypt :email, searchable?: true, unique?: true, normalize: :downcase_trim
end
```

That is a **deliberate disclosure**, not a free index. Read "The equality-leakage
tradeoff" below before you turn it on, and decide per column.

## Why the ciphertext itself is not searchable

AES-GCM draws a fresh random nonce for every write, so the same plaintext encrypts to
completely different bytes every time. `WHERE encrypted_email = $1` matches nothing, and a
unique index on `encrypted_email` constrains nothing: two rows holding the same address
look entirely unrelated to the database.

That is not a configuration AshVault withholds. It is what the encryption *is* — and it is
why the generated decrypt calculation is declared `filterable?: false, sortable?: false`.

So a searchable field carries two columns:

```
plaintext
  ├── AES-GCM → encrypted_email   (randomized, authenticated, unsearchable)
  └── HMAC    → email_lookup      (deterministic, indexable, one-way)
```

You query and constrain on `email_lookup`, and decrypt `encrypted_email` only after
finding the row.

## The key that makes the token is not the key that decrypts

This is the part to get right, and the part with no second chance.

The token key comes from `c:AshVault.KeyProvider.lookup_key/1`: a **separate,
non-rotating, per-scope** secret. It is not the data encryption key and is not derived
from it.

Per-field separation comes from HKDF (RFC 5869), not from a separate provider key per
field:

```
lookup_key_for_field =
  HKDF-SHA256(ikm:  provider_lookup_key(scope),
              info: "ash_vault:lookup:v1|" <> inspect(resource) <> "|" <> field)

email_lookup = HMAC-SHA256(lookup_key_for_field, normalize(plaintext))
```

Binding the resource and the field means the same address in two columns, or in two
resources, produces two unrelated tokens — the same separation the AEAD's additional
authenticated data gives the ciphertext. Binding the scope is what the per-scope provider
key already does.

Three properties follow, and all three are enforced, not merely documented:

* **`AshVault.rotate_key!/2` does not touch tokens.** Rotation mints a new data key
  version; the lookup key is untouched, so every stored token stays valid and every query
  keeps matching.

  If the lookup key *did* rotate, every row written before the rotation would silently
  stop matching its own value: no error, no log line, `unique?` quietly stops preventing
  duplicates, and users cannot log in. The regression guard for this lives in
  `test/ash_vault/lookup_rotation_test.exs`, and it asserts the provider hands back the
  identical key binary across a rotation rather than inferring it from token equality.

* **`AshVault.destroy_keys!/2` destroys the lookup key too**, gated by the same tombstone.
  Crypto-erasure stays total: after erasure a lookup raises
  `AshVault.Errors.KeyDestroyed` rather than returning zero rows, and the provider never
  mints a fresh lookup secret for a destroyed scope. A surviving lookup key would let
  anyone holding it keep confirming guesses about a subject whose data was "destroyed".

* **A provider without `lookup_key/1` is a compile-time DSL error** naming the provider,
  not a runtime surprise at the first login attempt.
  `AshVault.KeyProviders.Memory`, `AshVault.KeyProviders.Local` and
  `AshVault.KeyProviders.OpenBao` all implement it.

### Rotating a lookup key is a backfill, not a rotation

There is deliberately no `rotate_lookup_key` anywhere. Changing the lookup key
invalidates every stored token, so it is a data migration:

```bash
mix ash_vault.backfill MyApp.Accounts.User email --tenant acme --lookup
```

See [Migration](#migration) below.

## Querying

Never build a token by hand. One stray `String.downcase/1` and the query silently matches
nothing. There are two supported paths.

### `AshVault.Query.filter_by/4`

```elixir
MyApp.Accounts.User
|> AshVault.Query.filter_by(:email, "Jake@Example.com", tenant: "acme")
|> Ash.read!(tenant: "acme")
```

It returns an ordinary `Ash.Query`, so it composes:

```elixir
MyApp.Accounts.User
|> Ash.Query.filter(active == true)
|> AshVault.Query.filter_by(:email, "jake@example.com", tenant: "acme")
```

### The generated `:by_<field>` read action

`searchable?: true` also generates a read action taking the plaintext as a
`sensitive?: true` argument. That is the one to expose through a code interface — which
AshVault does **not** write for you, because the interface belongs to your domain:

```elixir
# in your domain
resource MyApp.Accounts.User do
  define :get_user_by_email, action: :by_email, args: [:email], get?: true
end

MyApp.Accounts.get_user_by_email!("jake@example.com", tenant: "acme")
```

### A missing tenant is an error, never an empty result

Both paths resolve the scope through the resource's configured `AshVault.Scope`, from the
query's tenant, exactly as a write does. A tenant-scoped query with no tenant fails with
`AshVault.Errors.MissingScope`.

This is the single most important behaviour here. A lookup that quietly returned zero rows
for a missing tenant would read as *"no such user"* — at a login form, at an
"is this address taken?" check, at a dedupe pass — and it would look entirely healthy in
review, in logs and in tests.

The two paths report it differently, on purpose:

* `filter_by/4` **raises**. It is a plain function with no query of its own to hang an
  error on.
* the generated read action adds the error to the query, so `Ash.read/2` returns
  `{:error, _}` and `Ash.read!/2` raises — the same contract every other Ash error and
  every other AshVault path honours. A preparation that raised would be the only place in
  AshVault where an error escapes a non-bang Ash call as an exception.

## Normalization

`normalize:` decides what "equal" means: `:none` (the default), `:downcase`,
`:downcase_trim`, or an MFA / 1-arity function returning a binary.

The default is `:none` deliberately. Silent normalization changes equality semantics, and
for an email field you should opt in knowingly.

> #### Normalization is applied to the stored value too {: .warning}
>
> The token must be the hash of exactly the bytes that were encrypted, so the *normalized*
> value is what gets encrypted. With `normalize: :downcase_trim`, writing
> `" Jake@Example.COM "` stores — and later decrypts to — `"jake@example.com"`.
>
> This is deliberate. A token that did not match the value sitting beside it would be
> worse: the row would be findable under one spelling and readable as another.

> #### Changing `normalize:` after rows exist is a one-way door {: .error}
>
> Exactly like changing a password hash function — except worse, because AshVault
> encrypts the normalized value. Existing rows keep both their old tokens *and* their old
> spelling in the ciphertext, so they stop matching, and there is no way to bring them
> back into agreement without re-encrypting them.
>
> `mix ash_vault.backfill --lookup` deliberately **refuses** to paper over this: on
> finding a row whose ciphertext does not match the current normalization it aborts,
> naming the row, rather than writing a token that would make the row findable under one
> spelling and readable as another. Decide `normalize:` before the column has rows in it.

Normalization operates on a binary. `searchable?: true` on a field whose type is not one
of `:string`, `:ci_string`, `:binary` or `:uuid` is a compile-time DSL error unless you
supply a custom `normalize:` MFA — AshVault will not `to_string/1` a struct for you.
`inspect/1` output is a stable-looking string that would quietly become the searchable
identity of the row, and two values differing only where `inspect/1` truncates would
collide.

## `unique?`

`unique?: true` adds an `Ash.Resource.Identity` named `<field>_lookup_unique` on
`[<field>_lookup]`, which gives you database-enforced uniqueness on a value the database
cannot read.

It requires `searchable?: true`, and says so at compile time if you forget: there is no
token to constrain otherwise, and a unique index on the randomized ciphertext constrains
nothing.

Two details worth knowing:

* **Uniqueness is per tenant.** The identity lists only `[<field>_lookup]`; Ash adds the
  multitenancy attribute itself — to the generated unique index, and to the eager/pre-check
  query — whenever the identity is not `all_tenants?`. Listing it in `keys` as well would
  be redundant in the index and would wrongly change the identity's public contract, since
  `keys` is what `Ash.get/3`-by-identity and upsert-by-identity require as inputs.
* **`nil` never conflicts.** `nils_distinct?` defaults to true, which is also what a plain
  Postgres unique index does: any number of rows may hold a nil value.

## Migration

`--lookup` covers two situations: an already-encrypted field that has just been given
`searchable?: true`, and a deliberate re-keying of the provider's lookup secret. It does
**not** cover a changed `normalize:` — see the warning above.

To make an existing encrypted field searchable:

1. **Expand** — an ordinary migration adds the `<field>_lookup` column and its index.
2. **Deploy** the resource with `searchable?: true` (and `unique?: true` only *after* step
   3, so the backfill is not fighting a constraint on half-populated data).
3. **Backfill** — `mix ash_vault.backfill MyApp.User email --tenant acme --lookup`. It
   reads, decrypts, normalizes, hashes, and writes **only** the token column; the
   ciphertext is never rewritten.

Like the ciphertext backfill it is resumable and idempotent with no state file: it selects
only rows whose token `IS NULL` and whose ciphertext `IS NOT NULL`, so a second run is a
no-op. `--verify` does not apply — an HMAC is one-way, so there is nothing to decrypt and
compare — and is refused rather than silently ignored.

## The equality-leakage tradeoff, stated plainly

A lookup token column is a deliberate disclosure. Anyone with the database — including
every historical backup — learns:

* **which rows share a value, with no key at all.** Two rows with the same token hold the
  same address. That is a deduplication oracle, a social graph and a re-identification
  vector. It is also exactly what makes the index work; you cannot have one without the
  other.
* **the frequency distribution.** The most common token in a `country` column is the most
  common country.
* **confirmation of a guess, if they also hold the lookup key.** With the key an attacker
  computes `HMAC(key, "alice@example.com")` and checks for its presence. They still cannot
  *decrypt* anything — the lookup key is HKDF-separated from the data key, so holding the
  ability to search is strictly weaker than holding the ability to read. But for a field
  with a small or enumerable domain, "confirm a guess" is equivalent to "recover the
  value" by brute force. HMAC is fast on purpose; it is not a password hash and does not
  pretend to be.

**Low-cardinality fields are a bad fit.** A `searchable?: true` boolean, a country code, a
blood type, a gender — these publish an equality map of your whole table and are close to
not encrypting the column at all. Say no to those.

Per-scope keys keep the leakage inside one tenant: a token in tenant A and a token in
tenant B are unrelated even for the same address, so a shared email never discloses a
cross-customer relationship your customers did not agree to.

### Why not deterministic encryption

Encrypting with a fixed nonce so that equal plaintexts produce equal ciphertexts is the
obvious shortcut, and it is explicitly not the mechanism.

* It destroys the AEAD guarantee. A fixed nonce under GCM is catastrophic: two messages
  under the same key and nonce leak their XOR and the authentication subkey, allowing
  forgery.
* It leaks the same equality relation anyway — so it buys nothing on that axis.
* It is **reversible with the key**, where an HMAC is one-way. The value that can be
  searched would also be the value that can be decrypted, so anything able to search could
  read.

## Related

* `AshVault.Lookup` — the derivation, and the HKDF implementation
* `AshVault.Query` — `filter_by/4` and the generated read action
* `c:AshVault.KeyProvider.lookup_key/1` — the provider contract
* [Threat model](threat-model.md) — the residual-risk entry for lookup tokens
* [Crypto-erasure](crypto-erasure.md) — why destroying the lookup key is part of erasure
