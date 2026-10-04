# AshVault DSL

All options live in the `ash_vault do ... end` section of a resource using
`extensions: [AshVault]`.

```elixir
ash_vault do
  vault MyApp.Vault
  scope :tenant
  encrypt :email, searchable?: true, unique?: true, normalize: :downcase_trim
  encrypt :ssn, encrypt_nil?: false
  attributes [:notes, :phone]
  decrypt_by_default [:email]

  scope_owner? true
  key_lifecycle do
    rotate :rotate_key
    destroy :destroy_keys
  end
end
```

## Section options

| Option | Default | Meaning |
|---|---|---|
| `vault` | required | A module using `AshVault.Vault`, an MFA, or a `fun/2` of `(resource, context) -> vault_module` |
| `scope` | `:tenant` | Key scope: `:tenant`, `:global`, or an `AshVault.Scope` module |
| `attributes` | `[]` | Shorthand: list of fields, each an `encrypt` with default options |
| `decrypt_by_default` | `[]` | Encrypted fields whose decrypt calculation loads automatically |
| `encrypt_nil?` | `true` | Encrypt `nil` (hides nullness) instead of storing SQL NULL; overridable per field |
| `scope_owner?` | `false` | This resource *is* the scope (tenant/organization). Required for `key_lifecycle` |

## `encrypt` entity options

`encrypt :name, opts`. The attribute must be declared in `attributes do` (its type,
constraints, `allow_nil?` and `public?` are preserved on the decrypt calculation).

| Option | Default | Meaning |
|---|---|---|
| `encrypt_nil?` | section value | Per-field override |
| `searchable?` | `false` | Also store `<name>_lookup` HMAC token and generate `:by_<name>` |
| `unique?` | `false` | Unique identity `<name>_lookup_unique` on the token, per tenant. Requires `searchable?` |
| `pre_check_with` | none | Ash domain to pre-check the unique identity against. Required for `unique?` on ETS/Mnesia; costs a read per write |
| `normalize` | `:none` | `:none`, `:downcase`, `:downcase_trim`, `{Mod, :fun, extra_args}`, or a 1-arity fun. Must return a binary |
| `backfill_from` | none | Existing plaintext attribute to read during `mix ash_vault.backfill` |

## `key_lifecycle` section

Generates generic actions that rotate or destroy this scope's keys. Names are yours.

- `rotate :rotate_key` returns the new key version.
- `destroy :destroy_keys` returns `{:ok, %AshVault.Erasure{scope: _, destroyed_at: _}}`.
- Requires `scope_owner? true`; otherwise a compile error. Put it on the tenant/organization
  resource only, not on every resource with encrypted fields.
- Actions are ordinary Ash generic actions: **add policies**. AshVault adds no authorization.
- Pass the tenant: `Ash.ActionInput.for_action(Org, :rotate_key, %{}, tenant: org_id)`.

## Do

- Declare every encrypted attribute in `attributes do` as well as `encrypt`.
- Restate a non-default scope on the resource: a vault built with `scope: AshVault.Scopes.Global`
  needs `scope :global` here. A mismatch is a compile error (otherwise rotate/destroy would hit
  the wrong keys).
- List only encrypted fields in `decrypt_by_default`; anything else is a compile error.

## Don't

- Don't list a field twice in `encrypt`/`attributes` (compile error).
- Don't use `searchable?` on non-string-like types (`:string`, `:ci_string`, `:binary`,
  `:uuid` are accepted) without a custom `normalize:` returning a binary.
- Don't add `identity`/custom indexes on an encrypted field. Use `unique?: true`.
- Don't set `backfill_from` to an attribute that does not exist (compile error) or to the
  `encrypted_<name>` column.
- Don't confuse `scope` with `Ash.Scope`: it is the *key* scope.

## `macaroon` entity

`macaroon :name do ... end` (with nested `caveat name, type, check:, phase:`) declares an
attenuable bearer token. See `usage-rules/macaroons.md`.
