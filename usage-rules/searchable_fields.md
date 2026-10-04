# Searchable fields

Encrypted fields cannot be filtered, sorted or prefix-matched. The only supported lookup is
**equality**, by opting a field in:

```elixir
ash_vault do
  vault MyApp.Vault
  encrypt :email, searchable?: true, unique?: true, normalize: :downcase_trim
end
```

This adds a private `email_lookup` `:binary` attribute (HMAC token, deterministic, indexable)
next to `encrypted_email`, plus a generated read action `:by_email`.

## Query it the supported way

```elixir
# Plain function; returns an Ash.Query, composes with other filters. RAISES on error.
MyApp.Accounts.User
|> Ash.Query.filter(active == true)
|> AshVault.Query.filter_by(:email, "Jake@Example.com", tenant: org_id)
|> Ash.read!(tenant: org_id)

# Generated action, exposed through your domain's code interface (AshVault does not write it):
define :get_user_by_email, action: :by_email, args: [:email], get?: true
MyApp.Accounts.get_user_by_email!("jake@example.com", tenant: org_id)
```

- `filter_by/4` context accepts `[tenant: t]`, an Ash context, `nil` (global scope) or a bare
  tenant. It raises `AshVault.Errors.MissingScope` without a tenant, `AshVault.Errors.KeyDestroyed`
  for an erased scope, and `ArgumentError` for a field that is not searchable.
- The `:by_<field>` action returns `{:error, _}` from `Ash.read/2` for a missing tenant
  (the error is added to the query, not raised).
- A missing tenant is an error, **never** an empty result. Do not "handle" it by returning
  `nil`/"not found": at a login form that would read as "no such user".
- Do not build tokens yourself or write `Ash.Query.filter(email_lookup == ^x)` with a hand-made
  value; one wrong `String.downcase/1` silently matches nothing. If you truly need a token,
  `AshVault.Lookup.token_for!/4` derives it from plaintext the way a write does (it takes an
  `%AshVault.Context{}`); for a token already in hand use `AshVault.Query.apply_filter/3`.
- A `nil` plaintext has no token; `filter_by` turns it into `is_nil`.

## `normalize:`

`:none` (default), `:downcase`, `:downcase_trim`, `{Mod, :fun, extra_args}` or a 1-arity
function; it must return a binary (else `AshVault.Errors.LookupNormalizationFailed`).

- The **normalized** value is encrypted *and* hashed, so it is what you read back. With
  `:downcase_trim`, `" Jake@Example.COM "` is stored and decrypted as `"jake@example.com"`.
- Choose it before any rows exist. Changing it later orphans existing tokens; no rotation or
  backfill repairs it (`mix ash_vault.backfill --lookup` aborts rather than write
  inconsistent rows).
- Fields of type other than `:string`, `:ci_string`, `:binary`, `:uuid` need a custom
  `normalize:` or the resource will not compile.

## `unique?: true`

Adds identity `<field>_lookup_unique` on the token. Requires `searchable?: true`. Unique **per
tenant**; `nil` never conflicts.

- PostgreSQL enforces it with a unique index; nothing else needed.
- ETS/Mnesia cannot: add `pre_check_with: MyApp.Domain`. It costs a read per write and is not
  race-free.
- Upsert by the encrypted field: `upsert? true, upsert_identity: :email_lookup_unique`. Never
  put the plaintext field in `upsert_fields` (it is a calculation, silently ignored); use
  `:encrypted_email` or omit `upsert_fields`.
- Declare `unique?` only after a backfill of existing data, so the constraint does not fight
  half-populated rows.
- Do not write `identity :unique_email, [:email]` yourself; it enforces nothing and is a
  compile error.

## Cost and risk

A token column discloses to anyone with the database (and every backup) **which rows share a
value** and the value frequency distribution. Per-scope keys keep that inside one tenant.

- Don't make low-cardinality fields searchable (booleans, country, status, blood type).
- Rotation does **not** change tokens (the lookup key is separate and non-rotating). Destroying
  a scope destroys its lookup key too.
- Provider must implement `lookup_key/1`: `Memory`, `Local` and `OpenBao` do;
  `OpenBaoTransit` does not (compile error on a `searchable?` field).
- Adding `searchable?: true` to an already-encrypted field: add the `<field>_lookup` column,
  deploy, then run `mix ash_vault.backfill MyApp.Accounts.User email --tenant acme --lookup`.

## AshAuthentication

`AshAuthentication.Strategy.Password` cannot use an AshVault-encrypted `identity_field`.
Use its hashing machinery with your own actions, and a sign-in read that does
`prepare {AshVault.Preparations.FilterByLookup, field: :email}` on a searchable field.
