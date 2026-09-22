# Writing a rotation policy

A rotation policy answers one question, per scope, per operation: *should this write mint
a new key version first?* It never decides anything about reads — a value is always
decrypted with the key version its envelope names.

The default, `AshVault.RotationPolicies.Manual`, answers "no" forever. Keys rotate only
when something explicitly asks: `mix ash_vault.rotate`, `AshVault.rotate_key!/2`, or a
`key_lifecycle` generic action.

## The contract

```elixir
@callback policy(scope :: term(), AshVault.Context.t()) :: AshVault.RotationPolicy.t()
```

It returns a struct, not a decision:

```elixir
%AshVault.RotationPolicy{
  strategy: :manual | :age | :provider,
  max_age: Duration.t() | nil,
  rotate_on_write?: boolean()
}
```

`AshVault.RotationPolicy.due?/3` interprets it:

* `:manual` and `:provider` → never due. Rotation is driven from outside.
* `:age` with a `max_age` → due once `key_info.created_at` is older than
  `now - max_age`, via `DateTime.shift/2` and `DateTime.compare/2`.

And `AshVault.Vault.Runtime` acts on it only when **both** hold:

```elixir
if policy.rotate_on_write? and RotationPolicy.due?(policy, key_info) do
```

So `rotate_on_write?` is the master switch and `strategy` is the schedule. A policy with
`strategy: :age` but `rotate_on_write?: false` is a *description* of when you intend to
rotate that nothing acts on automatically — which is a perfectly reasonable thing to
return if a scheduled job reads it and calls `AshVault.rotate_key!/2` itself.

`:provider` exists for key stores with their own rotation schedule (a KMS rotating on its
own clock). AshVault does not rotate those; it just keeps reading whatever
`current_key/1` returns.

## Failure modes that matter

### Rotation must never fail a write

This is the load-bearing rule. `AshVault.Vault.Runtime` logs a warning and continues with
the existing key when `rotate/1` fails:

```
AshVault: key rotation for scope "acme" failed (:timeout); continuing with the existing
key for MyApp.Accounts.User.email
```

A key that is a day past its rotation date is a hygiene problem. A write that 500s
because the key store was briefly slow is an outage. Do not build a policy that assumes
rotation will succeed.

### …except when the scope is destroyed

There is exactly one failure that is *not* best-effort. If `rotate/1` answers
`{:error, :destroyed}`, a write is racing a `destroy!` and the pre-destroy key is about to
become unusable. Falling back to it would produce a write that "succeeds" while storing
ciphertext nobody can ever read. The runtime raises `AshVault.Errors.KeyDestroyed`
instead. You get this for free — just do not reimplement rotation in your own policy
module and lose it.

### `policy/2` runs on every single write

It is on the hot path. Return a module attribute; do not hit the network, the database, or
a `GenServer` you might block on. If the policy needs external state, cache it (an ETS
table refreshed by a periodic task) and read the cache here.

### `:age` needs a truthful `created_at`

An `:age` policy is only as good as the provider's timestamps. A provider that fabricates
`created_at: DateTime.utc_now()` when its metadata is unavailable produces a key that is
never older than any `max_age`, so the policy silently never fires and nothing logs a
reason. That is why the provider contract suite asserts `created_at` is stable across
calls — see [Writing a key provider](writing-a-key-provider.md).

### Rotation is not re-encryption

A policy that rotates hourly does not make yesterday's rows any more protected: they still
carry `key_version: n` and still decrypt. Frequent rotation buys you a smaller blast
radius for *future* writes and a shorter window for a leaked key — nothing more, unless
you also re-encrypt. See [Rotation](../topics/rotation.md).

### Rotating per write is not a security upgrade

`max_age: Duration.new!(second: 0)` with `rotate_on_write?: true` mints a key version on
every write. Some providers charge per version, some list them all in metadata, and
`mix ash_vault.key_info` will print thousands of them. Every version has to be retained
forever for old rows to decrypt, so this is a monotonically growing liability. Do not do
it outside tests (where `AshVault.Test.Support.RotateOnWritePolicy` does exactly this, on
purpose, to make the rotation path deterministic).

## A worked example

Rotate at most once every 30 days, opportunistically on write, and never for scopes
that are still in a trial:

```elixir
defmodule MyApp.RotationPolicy do
  @moduledoc """
  Rotate a scope's key when it is older than 30 days, opportunistically on the next
  write. Trial scopes are left on `:manual` — they are short-lived, and a trial that
  never converts is erased wholesale rather than rotated.

  Rotation here is best-effort by construction: `AshVault.Vault.Runtime` logs and
  continues with the existing key if the provider cannot rotate, so a slow key store
  never fails a customer write.
  """

  @behaviour AshVault.RotationPolicy

  alias AshVault.RotationPolicy

  @monthly %RotationPolicy{
    strategy: :age,
    max_age: Duration.new!(day: 30),
    rotate_on_write?: true
  }

  @manual %RotationPolicy{strategy: :manual}

  @impl AshVault.RotationPolicy
  @spec policy(term(), AshVault.Context.t()) :: RotationPolicy.t()
  def policy(scope, _context) do
    # Read-only, in-memory lookup. `policy/2` is on every write's hot path.
    if MyApp.Tenants.trial?(scope), do: @manual, else: @monthly
  end
end
```

Two things worth noting about the signature. The `scope` is the resolved binary scope key,
so this is where per-tenant policy belongs. The `AshVault.Context.t()` gives you the
resource and field as well, if you want a shorter rotation period for one sensitive
column than for the rest — though remember every version you mint has to be retained
forever.

## Wiring it up

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault,
    key_provider: MyApp.KeyProviders.Sql,
    rotation_policy: MyApp.RotationPolicy
end
```

There is no resource-level rotation setting; the policy belongs to the vault, next to the
provider whose keys it rotates.

## The alternative: don't

For most applications the honest answer is a scheduled job and the default `:manual`
policy:

```
# once a quarter, per tenant
mix ash_vault.rotate MyApp.Accounts.Organization --all-tenants MyApp.Accounts.list_tenant_ids/0 --yes
```

This is easier to reason about, easier to audit, visible in your deploy logs, and does not
put a policy decision on the write path. Write a rotation policy when you need rotation to
be a property of the data rather than of your crontab.

## Testing it

`test/ash_vault/rotation_policy_test.exs` is the model. Assert:

* `due?/3` for the boundary cases — exactly at `max_age`, one second either side — by
  passing an explicit `now`, never `DateTime.utc_now()`;
* `:manual` and `:provider` are never due, whatever the `created_at`;
* a `nil` `created_at` is not due (it falls through to the catch-all clause rather than
  raising);
* end to end: encrypt, assert the stored envelope's `key_version` with
  `AshVault.Envelope.decode/1` — do not infer it — then encrypt again and assert the
  version moved (or did not);
* a provider whose `rotate/1` fails does **not** fail the write. Use
  `AshVault.Test.Support.FailingRotateProvider`.

## Related

* `AshVault.RotationPolicy`, `AshVault.RotationPolicies.Manual`
* [Rotation](../topics/rotation.md)
* [Operations](../topics/operations.md) — `mix ash_vault.rotate`, `mix ash_vault.key_info`
