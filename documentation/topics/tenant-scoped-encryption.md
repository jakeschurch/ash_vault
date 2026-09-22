# Tenant-scoped encryption

By default, every AshVault value is encrypted under a key belonging to the Ash tenant that
wrote it. One tenant, one key lineage, one blast radius — and one thing to destroy when
that customer asks to be deleted.

This page is about how the tenant becomes a key, and the three rules that keeps honest.

## How scope resolution works

`AshVault.Vault.Runtime` resolves the scope on **every** encrypt and every decrypt, as the
first thing it does:

```elixir
scope = resolve_scope!(ctx, opts, :encrypt)
```

It calls the **vault's** `:scope` module — `AshVault.Scopes.AshTenant` by default — with
the `%AshVault.Context{}` built at the Ash boundary. The scope key it returns does two
jobs at once:

1. it addresses key material and the tombstone in the provider, and
2. it is interpolated into the AAD bound into the ciphertext:
   `"ashvault:v1|" <> scope <> "|" <> inspect(resource) <> "|" <> field`.

Which is why the same tenant must always produce the same key, forever.

### Finding the tenant

`AshVault.Scopes.AshTenant` looks in two places, first non-nil wins:

1. the top-level `:tenant` field — where both Ash callback context structs carry it,
2. `source_context[:tenant]`, for contexts whose tenant only reached the source context.

Upstream of that, `AshVault.Context.Builder` has already normalized the two different Ash
callback structs into one plain map, and made two path-specific choices:

* **Write path** (`from_changeset/3`): `changeset.tenant` wins. It is authoritative and
  current. The callback context's copy of `source_context` is *stale* — Ash snapshots it
  during `for_create`/`for_update`, so anything a caller sets with
  `Ash.Changeset.set_context/2` afterwards never reaches `change/3`. The encrypt change
  rebuilds it from `changeset.context` inside the hook.
* **Read path** (`from_calculation/3`): the calculation context's `:tenant` wins, falling
  back to `source_context[:private][:tenant]` — the same fallback Ash's own calculation
  builder uses.

If neither yields a tenant, you get `AshVault.Errors.MissingScope`, not a fallback to a
shared key:

```
Cannot encrypt MyApp.Accounts.User.email because no Ash tenant was present.

This resource uses tenant-scoped encryption.
Pass a tenant when executing the Ash action or configure another AshVault scope.
```

The verb tracks the operation — the decrypt path says "Cannot decrypt". There is no
`context \\ nil` default anywhere in AshVault: silently encrypting tenant data under a
shared key, where it survives that tenant's erasure, is not a helpful fallback.

### `Ash.ToTenant` normalization

Ash hands AshVault the **raw** tenant. `Ash.Changeset`'s `:tenant` field is deliberately
*not* normalized — it may be a binary, an integer, an atom, or a whole `%Organization{}`
struct, depending on what the caller passed:

```elixir
Ash.create!(changeset, tenant: org)        # a struct
Ash.create!(changeset, tenant: org.id)     # a binary
```

Both of those must land on the same key, or one caller cannot read the other's rows.
`AshVault.Scopes.AshTenant.to_scope_key/2` does that normalization:

| Tenant | Scope key |
|---|---|
| a binary | itself |
| an atom | `Atom.to_string/1` |
| an integer | `Integer.to_string/1` |
| a struct with a non-nil `:id` | the stringified id |
| anything else | `MissingScope`, `reason: :unsupported_tenant_shape` |

Ash's own `Ash.ToTenant` protocol reduces a resource struct to its primary key for the
same reason; AshVault's struct clause agrees with it for the ordinary case of a
single-attribute primary key.

That last row is worth its own error branch, because the naive thing — falling through to
the missing-tenant message — sends an operator who *did* pass a tenant hunting for one
that is not missing:

```
Cannot encrypt MyApp.Accounts.User.email because the tenant is of a shape
AshVault.Scopes.AshTenant cannot turn into a stable scope key.

Received: %{org: "acme"}

A tenant was present — this is not a missing-tenant error. Accepted shapes are:

  * a binary, used as-is
  * an atom or an integer, stringified
  * a struct with a non-nil `:id`, reduced to the stringified id

To support another shape, implement `to_scope_key/2` in your own
`AshVault.Scope` module (see `AshVault.Scopes.AshTenant.to_scope_key/2`) and
configure it as the vault's `:scope`.
```

## Why the scope key must be a stable binary

Stringification, not hashing and not `:erlang.term_to_binary/1`. Two reasons, and they
compound.

**The provider.** The scope key names key material and the tombstone. If the key changes
value for the same logical tenant, the tombstone moves — so the provider sees an unknown
scope, mints a fresh version 1, and the erased tenant is **back**, writing new rows under
a new key while the old ones are unreadable.

**The AAD.** The scope key is bound into every ciphertext's authentication tag. If it
changes, every existing row of that tenant fails with
`AshVault.Errors.AuthenticationFailed` — erasure wearing the costume of tampering.

`:erlang.term_to_binary/1` output is explicitly not guaranteed stable across OTP releases,
so an OTP upgrade would do both at once. AshVault enforces the binary half in exactly one
place, `AshVault.Vault.Runtime`, right after `resolve!/1` returns:

```
MyApp.Scopes.Custom.resolve!/1 returned {:tenant, "acme"}, which is not a binary.

AshVault scope keys must be binaries: they name key material in the provider and are
bound into every ciphertext's associated data, so they have to be stable across
processes, releases and OTP upgrades.
```

That is `AshVault.Errors.InvalidScope`. Every built-in provider independently rejects a
non-binary scope with an `ArgumentError` too, and the shared contract suite asserts all
three do it identically — a custom scope must not be able to pass tests against one
provider and behave differently against another.

Stringification also keeps scope keys *legible*, which matters operationally: an operator
can map a tenant to its directory (`AshVault.KeyProviders.Local.scope_dir/1`) or its
transit key name (`AshVault.KeyProviders.OpenBao.key_name/1`) and back.

## The scope-agreement rule the verifier enforces

A resource declares a scope, and so does its vault:

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault, key_provider: MyApp.KeyProvider   # scope defaults to AshTenant
end

ash_vault do
  vault MyApp.Vault
  scope :tenant
  encrypt :email
end
```

These are **not** the same setting, and they do different things:

* The **vault's** scope is what data is actually encrypted under.
  `AshVault.Vault.Runtime` resolves it, per operation.
* The **resource's** scope is what the `key_lifecycle` generic actions rotate and destroy,
  and what the mix tasks resolve a `--tenant` against.

If they disagree, rotation and cryptographic erasure act on different keys than the data
was written with — you would destroy a scope, get a success message, and the data would
still be readable. `AshVault.Verifiers.VerifyVault` refuses to compile that:

```
This resource's key scope is AshVault.Scopes.AshTenant but MyApp.Vault encrypts with
MyApp.Scopes.PerUser.

The vault resolves the scope every value is actually encrypted under, while the
resource's `scope` is what the `key_lifecycle` actions rotate and destroy. If the
two disagree, rotation and cryptographic erasure act on the wrong keys.

Either set `scope` to match the vault, or point at a vault built with
`use AshVault.Vault, scope: AshVault.Scopes.AshTenant`.
```

> #### You must restate a non-default scope on the resource {: .warning}
>
> Spark materializes schema defaults into the DSL state, so
> `Spark.Dsl.Extension.fetch_opt/3` cannot tell a *written* `scope :tenant` from the
> default one. Rather than let a silent mismatch through, AshVault requires the resource
> to restate anything that is not the default.
>
> Both defaults are `AshVault.Scopes.AshTenant`, so the common case never trips. But a
> vault built with `scope: AshVault.Scopes.Global` needs `scope :global` on every resource
> using it, and a vault built with `scope: MyApp.Scopes.PerUser` needs
> `scope MyApp.Scopes.PerUser`.
>
> This is stricter than `docs/EXTENSION_SPEC.md` §1 describes, deliberately.

Two matching pairs, for reference:

```elixir
defmodule MyApp.GlobalVault do
  use AshVault.Vault,
    key_provider: MyApp.KeyProvider,
    scope: AshVault.Scopes.Global
end

defmodule MyApp.Notes do
  use Ash.Resource, extensions: [AshVault]

  ash_vault do
    vault MyApp.GlobalVault
    scope :global          # required: the vault's scope is not the default
    encrypt :body
  end
end
```

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource, extensions: [AshVault]

  ash_vault do
    vault MyApp.Vault      # AshTenant on both sides — nothing to restate
    encrypt :email
  end
end
```

## One tenant key spans every resource

A tenant has **one** key lineage, shared by every encrypted field of every resource in that
tenant. That is what makes "erase this customer" a single operation rather than a table
sweep.

The AAD still keeps their ciphertexts apart. `users.encrypted_email` and
`contacts.encrypted_phone` are encrypted with the same key but different associated data,
so moving one blob into the other's column fails authentication rather than decrypting
into the wrong field. Same key, different binding.

A consequence worth planning for: erasure is per scope, not per row or per table.
Destroying tenant A's key makes *all* of A's encrypted fields unreadable at once. If your
retention policy is per-record, the scope has to be per-record — see
[Writing a scope](../how-to/writing-a-scope.md), and budget one provider key per row.

## Working with tenants in practice

Pass the tenant exactly as you would for any Ash multitenant operation. AshVault adds no
call-site ceremony:

```elixir
MyApp.Accounts.User
|> Ash.Changeset.for_create(:create, %{org_id: org.id, email: "a@b.c"}, tenant: org.id)
|> Ash.create!()

MyApp.Accounts.User
|> Ash.Query.load([:email])
|> Ash.read!(tenant: org.id)
```

Either attribute or schema multitenancy works. AshVault's own test suite uses **attribute**
multitenancy (`org_id`), which keeps a `pg_dump`/restore acceptance test to a single schema
and makes cross-tenant ciphertext substitution expressible as a plain `UPDATE`.

Three things that will bite you:

* **Background jobs, migrations and mix tasks need the tenant too.** Anything that reads or
  writes an encrypted field without one gets `MissingScope`. This is why every `ash_vault.*`
  task takes `--tenant`, or `--all-tenants` naming a zero-arity function.
* **`decrypt_by_default` does not exempt you.** Loading a field automatically still resolves
  a scope; automatic is not tenant-free.
* **Cross-tenant reads.** The decrypt calculation is left at Ash's default
  `multitenancy: :enforce`. A resource that genuinely needs to decrypt across tenants —
  an internal admin view, say — needs Ash's calculation multitenancy escape hatch, and even
  then each row still resolves its own scope from the context it is read in, so a
  cross-tenant read of another tenant's row will fail on the AAD. The honest answer for
  that use case is to read per tenant.

## Related

* [Architecture](architecture.md) — `AshVault.Context` and where it comes from
* [Writing a scope](../how-to/writing-a-scope.md) — per-user, per-row, per-region
* [Crypto-erasure](crypto-erasure.md) — what destroying a tenant's key does
* `AshVault.Scopes.AshTenant`, `AshVault.Scopes.Global`, `AshVault.Verifiers.VerifyVault`
