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
* **It is Postgres-shaped.** A data layer with no unique constraint of its own — ETS,
  Mnesia — cannot enforce an identity, and Ash refuses to accept one there unless it is
  given a domain to pre-check against. AshVault will not set that for you, so
  `unique?: true` on such a resource is a DSL error until you opt in:

  ```elixir
  encrypt :email, searchable?: true, unique?: true, pre_check_with: MyApp.Domain
  ```

  The opt-in is deliberate. `pre_check_with` works — the pre-check hook runs after the
  encrypt hook, so the token is on the changeset when the check queries for it, and a
  duplicate really is rejected, normalization and all — but it is a full read action on
  **every write**, and it is not race-free: two concurrent creates can both see no
  conflict. That is the honest ceiling on a data layer with no unique constraint, and it
  is not a cost to add to someone's write path silently. PostgreSQL needs none of it: the
  generated identity carries no `pre_check_with` there, and the unique index does the
  work.

## What `unique?` unlocks

### Upsert by an encrypted field

`upsert_identity: :<field>_lookup_unique` makes "create or update this user by email"
work, which is the thing people reach for the moment they have a unique encrypted column:

```elixir
create :register_or_update do
  accept [:org_id, :email]

  upsert? true
  upsert_identity :email_lookup_unique
end
```

```elixir
MyApp.User
|> Ash.Changeset.for_create(:register_or_update, %{org_id: org, email: "Jake@Example.com"})
|> Ash.create!(tenant: org)
```

The encrypt hook runs in `before_action`, so the natural worry is whether the token exists
by the time Ash resolves the identity. It does, and the question turns out to be moot in
both directions:

* the identity's `keys` are only ever read as **column names** — Ash turns them into the
  `ON CONFLICT` target and adds the multitenancy attribute itself. The emitted statement is

  ```sql
  INSERT INTO "users" (..., "email_lookup", "encrypted_email") VALUES (...)
  ON CONFLICT ("org_id", "email_lookup")
  DO UPDATE SET "encrypted_email" = EXCLUDED."encrypted_email"
  ```

* the identity is never eager- or pre-checked: Ash short-circuits identity validation for
  the identity being upserted on, and the generated identity sets neither
  `eager_check_with` nor `pre_check_with` anyway.

The values are read at data-layer time, inside `Ash.Changeset.with_hooks/3` — after every
`before_action` hook — so the ciphertext and the token are ordinary changeset attributes
by then.

Four behaviours to know before you use it:

* **The update half re-encrypts.** The `DO UPDATE SET` list carries `encrypted_email`, so
  the row gets a fresh nonce and fresh ciphertext. The token, being deterministic, does
  not move.
* **Uniqueness stays per tenant.** Two tenants upserting the same address get two rows —
  and not only because `org_id` is in the conflict target: the token key is per scope, so
  the two tokens differ as well.
* **A `nil` value inserts, every time.** A nil plaintext produces a nil token, and
  `ON CONFLICT` never matches NULL. "Upsert by email" with no email is an INSERT, forever.
  That is correct — there is no key to match on — and completely silent.
* **Never name the field itself in `upsert_fields`.** `upsert_fields: [:email]` does not
  raise. `:email` is a *calculation* now, AshPostgres filters it out of the list as "not an
  attribute that is changing", the list empties, and the empty case falls back to the
  conflict keys — producing `DO UPDATE SET "org_id" = EXCLUDED."org_id", "email_lookup" =
  EXCLUDED."email_lookup"`, an update that writes the row's own key back over itself. The
  ciphertext is silently not updated. Write `upsert_fields: [:encrypted_email]`, or leave
  the option out and take the default, which is correct.

Changing `normalize:` after rows exist interacts with this exactly as it does with every
other lookup: the old rows hash to different tokens, `ON CONFLICT` stops firing for them,
and an "upsert" inserts a second row for an address that is already there. It is a
backfill, not a rotation — see [Migration](#migration).

### `Ash.get/3` by the generated identity

The identity is an ordinary one, so it works as an `Ash.get/3` key — with the token, not
the plaintext, because `keys` is `[:email_lookup]`:

```elixir
token = AshVault.Lookup.token_for!(MyApp.User, :email, "jake@example.com", context)

{:ok, user} = Ash.get(MyApp.User, [email_lookup: token], tenant: "acme")
```

Prefer `AshVault.Query.filter_by/4` or the generated `:by_<field>` action for ordinary
lookups: they take the plaintext and build the token for you, with the scope resolved the
same way a write resolves it. Reach for `Ash.get/3` when you already hold a token — the
one case being code that read the column and now wants the row back.

### Finding duplicates: `GROUP BY <field>_lookup`

Before you can add `unique?: true` to an existing column you have to know whether it is
already unique. The token column answers that with no key and no decryption at all:

```sql
SELECT email_lookup, count(*), array_agg(id)
FROM users
WHERE org_id = $1 AND email_lookup IS NOT NULL
GROUP BY email_lookup
HAVING count(*) > 1;
```

Then resolve a group back to rows through an ordinary filter — still without decrypting
anything:

```elixir
MyApp.User
|> Ash.Query.filter(email_lookup == ^token)
|> Ash.read!(tenant: org)
```

Two caveats:

* **The group means "same normalized value", not "same email".** `:downcase_trim` puts
  `" Jake@Example.COM "` and `"jake@example.com"` in one group; `:none` does not. The
  column implements exactly one equality relation, and it is the one `normalize:` chose.
* **Duplicates never span tenants.** Each scope has its own token key, so a `GROUP BY`
  across the whole table can only ever group rows within one tenant. That is the leakage
  boundary working as intended — and it means dedupe is a per-tenant job.

This query is also, uncomfortably, exactly what an attacker with a database dump runs. See
[the equality-leakage tradeoff](#the-equality-leakage-tradeoff-stated-plainly).

## AshAuthentication

A password login has to find a user by email before it can check a password, so a
searchable field is the only thing that makes an encrypted email column compatible with
authentication at all. The lookup side works, and works well. The
`AshAuthentication.Strategy.Password` **DSL** does not — it cannot be pointed at an
AshVault-encrypted `identity_field`, for three independent reasons, all of them downstream
of the same fact: `encrypt` removes the plaintext attribute.

1. `identity_field` must name an attribute that is uniquely constrained, i.e.
   `identity :unique_email, [:email]`. That identity enforces nothing once the attribute is
   a calculation — there is no column for the index to cover — and
   `AshVault.Verifiers.VerifyVault` rejects it as a DSL error for exactly that reason.
2. The register action AshAuthentication generates carries
   `require_attributes: [identity_field]`, and Ash dereferences that name as an attribute
   while building the changeset. The attribute is gone, so the first registration raises
   `BadMapError`.
3. `SignInPreparation` filters `ref(identity_field) == ^identity`. The decrypt calculation
   is `filterable?: false`, so that is an `Ash.Error.Query.InvalidFilterReference`. A
   hand-written sign-in action cannot route around it, because AshAuthentication *requires*
   that preparation to be present on whatever action `sign_in_action_name` names.

Tenant threading — the thing that looks most likely to break — is fine:
`AshAuthentication.Strategy.Password.Actions.sign_in/3` passes its options straight into
`Ash.Query.for_read/4`, so `tenant:` reaches the query.

What does work, and is what the example application demonstrates end to end, is using
AshAuthentication's password *machinery* with AshVault's lookup:

```elixir
create :register do
  accept [:org_id, :email]

  argument :password, :string, allow_nil?: false, sensitive?: true
  argument :password_confirmation, :string, allow_nil?: false, sensitive?: true

  validate confirm(:password, :password_confirmation)
  change MyApp.HashPassword          # AshAuthentication.BcryptProvider.hash/1
end

read :sign_in do
  argument :email, :string, allow_nil?: false, sensitive?: true
  argument :password, :string, allow_nil?: false, sensitive?: true

  prepare {AshVault.Preparations.FilterByLookup, field: :email}
  prepare MyApp.VerifyPassword       # AshAuthentication.BcryptProvider.valid?/2
  get? true
end
```

The hash is byte-for-byte what a stock AshAuthentication application stores, the miss path
still calls `simulate/0`, and a sign-in with no tenant raises
`AshVault.Errors.MissingScope` rather than reading as "no such user". `example/` has the
whole thing, and `mix example.demo` narrates it.

AshVault does **not** depend on ash_authentication. It is a dev/test dependency of the
library and an ordinary dependency of the example application.

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
* `example/lib/example/accounts/auth_user.ex` — a runnable password login over an
  encrypted, searchable email address
