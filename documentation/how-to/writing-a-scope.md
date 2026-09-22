# Writing a scope

A scope is the **blast radius of a key**. Everything sharing a scope shares key material,
and destroying that scope's key crypto-erases all of it at once. Choosing the scope is
therefore the most consequential design decision in an AshVault deployment: it decides
what "delete this customer's data" can mean.

AshVault ships two implementations:

* `AshVault.Scopes.AshTenant` — one key lineage per Ash tenant. The default, and the right
  answer for almost every multitenant application.
* `AshVault.Scopes.Global` — the constant `"global"`. One key lineage for the whole
  application; rotation and erasure are application-wide.

You write your own when the unit of erasure is neither of those — per-user in a
single-tenant app, per-row for a data-retention regime, per-region for a residency one.

## The contract

```elixir
@callback resolve!(AshVault.Context.t()) :: term()
```

One function. It receives the context of the operation and returns the scope key, or
raises `AshVault.Errors.MissingScope` if it cannot.

### The scope key must be a stable binary

`AshVault.Vault.Runtime` enforces the binary part in one place, right after
`resolve!/1` returns:

```
MyApp.Scopes.PerUser.resolve!/1 returned {:user, "u_1"}, which is not a binary.

AshVault scope keys must be binaries: they name key material in the provider and are
bound into every ciphertext's associated data, so they have to be stable across
processes, releases and OTP upgrades.
```

That is `AshVault.Errors.InvalidScope`. The *stable* part it cannot enforce, and it
matters more. The scope key is used for two things at once:

1. it names key material and the tombstone in the provider, and
2. it is interpolated into the AAD of every ciphertext:
   `"ashvault:v1|" <> scope <> "|" <> inspect(resource) <> "|" <> field`.

So a scope key that changes value for the same logical subject is a double failure: the
tombstone moves (the scope **resurrects** with a freshly minted key) and the AAD no longer
matches (every existing ciphertext fails to authenticate).

Concretely, never do this:

```elixir
# WRONG — :erlang.term_to_binary/1 output is not guaranteed stable across OTP releases
def resolve!(ctx), do: :erlang.term_to_binary(ctx.ash_context.tenant)

# WRONG — a hash of a mutable field. Rename the org, lose the data.
def resolve!(ctx), do: Base.encode16(:crypto.hash(:sha256, ctx.ash_context.tenant.name))
```

Do this instead: derive from an immutable identifier and stringify.

```elixir
def resolve!(ctx), do: "user:" <> to_string(id)
```

A prefix is worth adding. It keeps two different scope kinds from colliding in the same
provider namespace, and it makes a directory listing or a `bao list transit/keys`
legible.

### `Ash.ToTenant` normalization

Ash hands you the **raw** tenant. It may be a binary, an integer, an atom, or a whole
`%Organization{}` struct — `Ash.Changeset`'s `:tenant` field is deliberately not
normalized. Two callers passing the same logical tenant in different shapes must produce
the same scope key, or one of them cannot read the other's rows.

`AshVault.Scopes.AshTenant.to_scope_key/2` handles this:

* a binary is used as-is,
* an atom or integer is stringified,
* a struct with a non-nil `:id` is reduced to the stringified id,
* anything else raises `MissingScope` with `reason: :unsupported_tenant_shape`.

That last branch is worth copying. The naive thing is to fall through to the
missing-tenant error, which tells an operator who *did* pass a tenant to go and find the
tenant they did not forget:

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

If you accept a struct shape Ash's own `Ash.ToTenant` protocol already understands,
prefer calling `Ash.ToTenant.to_tenant/2` and stringifying the result, so a tenant struct
and its id land on the same key.

## Failure modes that matter

* **Never fall back to a default scope.** A `resolve!/1` that returns `"global"` when no
  tenant is present will silently encrypt tenant data under the shared key, and that data
  survives the tenant's erasure. A missing scope is an error, full stop — which is why
  there is no `context \\ nil` default anywhere in AshVault.
* **Never make the scope depend on the actor** unless the actor *is* the scope. If the
  scope varies with who is reading, the AAD varies too, and a row written by one user
  cannot be read by another.
* **Do not put the field or resource in the scope key.** They are already in the AAD. Adding
  them to the scope multiplies your provider keys by your column count for no gain, and
  makes erasure per-column instead of per-subject.
* **Per-row scopes cost one provider key per row.** That is the honest price of row-level
  crypto-erasure, and for some providers it is prohibitive. Measure before committing.
* **Read the context defensively.** `ash_context` is a normalized map on the Ash paths
  (`%{tenant:, actor:, source_context:, phase:}`) but the crypto core promises no more
  than "a map, a struct, or `nil`" — a plain map works, which is what direct vault calls
  and tests use.

## A worked example

Per-user scoping, for a single-tenant application that must honour individual deletion
requests. The user id travels in the Ash context rather than as a tenant.

```elixir
defmodule MyApp.Scopes.PerUser do
  @moduledoc """
  One key lineage per user, so a single user's data can be crypto-erased without
  touching anyone else's.

  The user id is read from `source_context[:user_id]`, set by the caller:

      MyApp.Note
      |> Ash.Changeset.for_create(:create, %{body: body})
      |> Ash.Changeset.set_context(%{user_id: user.id})
      |> Ash.create!()

  Costs one provider key per user. Erasure is
  `AshVault.destroy_keys!(MyApp.Vault, "user:" <> user.id)`.
  """

  @behaviour AshVault.Scope

  alias AshVault.Context
  alias AshVault.Errors.MissingScope

  @impl AshVault.Scope
  @spec resolve!(Context.t()) :: binary()
  def resolve!(%Context{} = context) do
    case user_id(context) do
      nil ->
        raise MissingScope.exception(
                resource: context.resource,
                field: context.field,
                scope_module: __MODULE__,
                reason: :no_user_id
              )

      id when is_binary(id) ->
        "user:" <> id

      %_struct{id: id} when is_binary(id) ->
        "user:" <> id

      other ->
        raise MissingScope.exception(
                resource: context.resource,
                field: context.field,
                scope_module: __MODULE__,
                reason: :unsupported_tenant_shape,
                tenant: inspect(other, limit: 5, printable_limit: 128, structs: false)
              )
    end
  end

  defp user_id(%Context{ash_context: ash_context}) when is_map(ash_context) do
    case get_in(ash_context, [Access.key(:source_context, %{}), :user_id]) do
      nil -> get_in(ash_context, [Access.key(:source_context, %{}), :private, :user_id])
      id -> id
    end
  end

  defp user_id(%Context{}), do: nil
end
```

`MissingScope.message/1` has a branch for a `:reason` it does not specifically know, so
`:no_user_id` produces:

```
Cannot encrypt MyApp.Note.body: MyApp.Scopes.PerUser could not resolve a scope (:no_user_id).
```

## Wiring it up

The scope lives on the **vault** — that is the one `AshVault.Vault.Runtime` actually
resolves with:

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault,
    key_provider: MyApp.KeyProviders.Sql,
    scope: MyApp.Scopes.PerUser
end
```

And the resource must **restate** it:

```elixir
ash_vault do
  vault MyApp.Vault
  scope MyApp.Scopes.PerUser

  encrypt :body
end
```

`AshVault.Verifiers.VerifyVault` enforces that agreement at compile time, because the
resource's `scope` is what the `key_lifecycle` actions rotate and destroy while the
vault's is what data is encrypted under. If they disagree:

```
This resource's key scope is AshVault.Scopes.AshTenant but MyApp.Vault encrypts with
MyApp.Scopes.PerUser.

The vault resolves the scope every value is actually encrypted under, while the
resource's `scope` is what the `key_lifecycle` actions rotate and destroy. If the
two disagree, rotation and cryptographic erasure act on the wrong keys.

Either set `scope` to match the vault, or point at a vault built with
`use AshVault.Vault, scope: AshVault.Scopes.AshTenant`.
```

See [Tenant-scoped encryption](../topics/tenant-scoped-encryption.md) for why the check is
a *restatement* rather than an inference.

## Testing it

`test/ash_vault/scopes/ash_tenant_test.exs` is the model. Assert:

* every shape you accept maps to the key you expect, and two shapes of the same subject
  map to the **same** key;
* a missing subject raises `MissingScope`, and `Exception.message/1` on it reads the way
  you want at 3am;
* a shape you do not accept raises `MissingScope` with `reason: :unsupported_tenant_shape`
  and *not* the missing-subject message;
* an end-to-end vault roundtrip through a vault configured with your scope, plus a
  cross-scope decrypt that fails with `AshVault.Errors.AuthenticationFailed`. Use a
  fixed-key provider for that last one (see `AshVault.Test.Support.FixedKeyVault`) — with
  per-scope keys the failure could be the key differing rather than the AAD binding, and
  the test would not prove what it claims.

## Related

* `AshVault.Scope`, `AshVault.Scopes.AshTenant`, `AshVault.Scopes.Global`
* [Tenant-scoped encryption](../topics/tenant-scoped-encryption.md)
* [Crypto-erasure](../topics/crypto-erasure.md) — "erasure is per scope, not per row"
