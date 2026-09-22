# Rotation

Three different operations get confused with each other. They are not interchangeable.

| Operation | What it does | Old rows | Reversible |
|---|---|---|---|
| **Rotation** | Mints a new key version for a scope | keep decrypting, unchanged on disk | n/a — nothing was lost |
| **Re-encryption** | Rewrites rows under the current key version | rewritten, byte-for-byte different | n/a — plaintext preserved |
| **Erasure** | Destroys every key version and tombstones the scope | permanently unreadable | **no** |

Rotation is cheap and safe. Re-encryption is expensive and safe. Erasure is instant and
irreversible. Only the third one makes data go away.

## Why old ciphertext keeps decrypting

Every envelope carries the key version that produced it:

```
<<"AV", 1::8, cid_len::8, cipher_id::binary, key_version::32-unsigned-big, ...>>
```

On decrypt, `AshVault.Vault.Runtime` reads that field and asks the provider for *that*
version — `get_key(scope, env.key_version)` — not for the current one. Providers retain
history: `rotate/1` mints version *n+1* and every previous version stays fetchable.

So rotation touches exactly nothing in the database. A table with a hundred million
encrypted rows rotates in one API call, and the rows are untouched, unlocked and unmoved.

You can see it directly. `test/acceptance/rotation_test.exs` decodes the raw column bytes
rather than inferring anything from "decryption succeeded":

```elixir
row1 = create!(tenant, "one@example.invalid", "111-11-1111")
assert stored_key_version(row1.id) == 1

assert {:ok, 2} = AshVault.rotate_key!(vault, tenant)
row2 = create!(tenant, "two@example.invalid", "222-22-2222")

assert stored_key_version(row1.id) == 1     # untouched
assert stored_key_version(row2.id) == 2     # new writes use the new version
```

where `stored_key_version/1` is:

```elixir
defp stored_key_version(id) do
  {:ok, %{key_version: version}} = Envelope.decode(raw_blob(id))
  version
end
```

Both rows still read back their plaintext through `Ash.read/2`.

## What rotation actually buys you

Be clear-eyed about this, because it is easy to over-claim.

It **does** limit the blast radius of a key compromise *going forward*. A key leaked today
opens the rows written while it was current, and nothing after the next rotation.

It **does** satisfy the control in most compliance regimes that asks for periodic key
rotation, and it gives you a cheap, low-risk operation to exercise on a schedule so the
key path is not something you only touch during an incident.

It **does not** protect data already written. Yesterday's rows still carry
`key_version: n` and still open with key *n*. Rotating hourly does not change that. If a
key is *known* compromised, rotation alone is not the remedy — you need re-encryption, and
probably an incident review about what else that key opened.

It **does not** delete anything. That is [crypto-erasure](crypto-erasure.md).

## Running a rotation

```
mix ash_vault.rotate MyApp.Accounts.Organization --tenant acme
```

```
ash_vault.rotate=done resource=MyApp.Accounts.Organization tenant=acme scope=acme \
  vault=MyApp.Vault provider=AshVault.KeyProviders.OpenBao old_version=2 new_version=3
Rotated MyApp.Vault scope acme: key version 2 -> 3.
```

Across every tenant, non-interactively, from a deploy script:

```
mix ash_vault.rotate MyApp.Accounts.Organization \
  --all-tenants MyApp.Accounts.list_tenant_ids/0 --yes
```

`--all-tenants` takes a string naming a zero-arity function (`Module.function` plus
`/0`) that returns a list of tenants. For a
`scope :global` resource, pass neither flag:

```
mix ash_vault.rotate MyApp.Notes
```

From code:

```elixir
{:ok, 3} = AshVault.rotate_key!(MyApp.Vault, "acme")
```

Or as a generic action on the scope-owning resource, which runs through ordinary Ash
policies and actors:

```elixir
MyApp.Accounts.Organization
|> Ash.ActionInput.for_action(:rotate_key, %{}, tenant: org, actor: admin)
|> Ash.run_action!()
#=> {:ok, 3}
```

Rotating a **destroyed** scope is an error and exits non-zero. The tombstone is permanent,
and re-minting would turn crypto-erasure into silent data loss:

```
** (Mix) scope acme has been destroyed; its keys can never be re-minted.
```

Rotating a scope that has never been used mints version 1 and returns `{:ok, 1}` — the
same thing `current_key/1` would have done on first write.

Check the state afterwards without minting anything:

```
mix ash_vault.key_info MyApp.Accounts.Organization --tenant acme
```

```
ash_vault.key_info=scope resource=MyApp.Accounts.Organization tenant=acme scope=acme \
  vault=MyApp.Vault provider=AshVault.KeyProviders.OpenBao key_name=ashvault_YWNtZQ \
  status=active version=3 created_at=2026-02-01T10:12:00Z versions=1,2,3
MyApp.Vault: scope acme is active at key version 3 (3 version(s) retained).
```

`versions=1,2,3` is the retained history — the versions old rows can still be opened with.

## Automatic rotation: the policy

A vault's `:rotation_policy` can opt into opportunistic rotation on write. The default,
`AshVault.RotationPolicies.Manual`, never does:

```elixir
%AshVault.RotationPolicy{strategy: :manual, max_age: nil, rotate_on_write?: false}
```

`AshVault.Vault.Runtime` consults it on every encrypt, and rotates only when **both** the
master switch and the schedule agree:

```elixir
if policy.rotate_on_write? and RotationPolicy.due?(policy, key_info) do
```

`AshVault.RotationPolicy.due?/3` is:

* `:manual` and `:provider` → never due. Rotation is driven from outside — a mix task, a
  scheduled job, or the key store's own schedule.
* `:age` with a `max_age` (an `Elixir.Duration`) → due once `key_info.created_at` is older
  than `now - max_age`.

### Rotation never fails a write

This is the rule that shapes the whole feature. When `rotate/1` fails during a write,
`AshVault.Vault.Runtime` logs and continues with the existing key:

```
AshVault: key rotation for scope "acme" failed (:timeout); continuing with the existing
key for MyApp.Accounts.User.email
```

A key a day past its rotation date is a hygiene problem; a write that 500s because the key
store was briefly slow is an outage. The tradeoff is deliberate.

There is exactly one exception. If `rotate/1` answers `{:error, :destroyed}`, the write is
racing a `destroy!` and falling back to the pre-destroy key would store ciphertext nobody
can ever read. That raises `AshVault.Errors.KeyDestroyed` and the write fails, which is the
recoverable outcome.

### The timestamp has to be real

An `:age` policy is only as good as the provider's `created_at`. A provider that fabricates
`DateTime.utc_now()` when its metadata is unavailable produces a key that is never older
than any `max_age`, so the policy silently never fires and nothing logs a reason. The
shared provider contract suite asserts `created_at` is stable across calls and never moves
backwards across a rotate, precisely to keep this honest.

### Prefer a scheduled task

For most applications, the default `:manual` policy plus a quarterly job is the better
answer: easier to reason about, visible in deploy logs, auditable, and it keeps a policy
decision off the write path. Write a rotation policy when rotation needs to be a property
of the data rather than of your crontab. See
[Writing a rotation policy](../how-to/writing-a-rotation-policy.md).

## Re-encryption

There is no re-encryption task in v1, and no `mix ash_vault.reencrypt`. The mechanism is
to read and re-save the rows: a write re-encrypts under the vault's *current* key version
and current cipher.

```elixir
MyApp.Accounts.User
|> Ash.Query.load([:email, :ssn])
|> Ash.stream!(tenant: "acme", authorize?: false, batch_size: 500)
|> Enum.each(fn user ->
  user
  |> Ash.Changeset.for_update(:update, %{email: user.email, ssn: user.ssn},
    tenant: "acme",
    authorize?: false
  )
  |> Ash.update!()
end)
```

Things to know before you run that:

* It decrypts and re-encrypts every row, one round trip to the key provider per row on
  each side. It is I/O bound on the provider. Batch it, rate-limit it, and run it out of
  hours.
* It runs the resource's ordinary update actions — including your changes, validations and
  notifiers. That is usually what you want (it is a real update), but it is not a
  transparent operation.
* It is not resumable on its own. If you need that, filter on something that records
  progress, or decode the stored envelope's `key_version` and select rows below the
  current one.
* It changes every ciphertext byte, including the nonce, so it is visible in your WAL and
  your replication lag. Do not run it on a hundred million rows in one go.

You need re-encryption when a key is known compromised, when you are migrating to a
different cipher, or when you want to retire old key versions from the provider. You do
**not** need it for ordinary rotation — that is the entire point of the key version in the
envelope.

## Retiring old key versions

Providers retain every version, forever, by default. A version can only be dropped once no
row references it — which, in practice, means after a full re-encryption pass. AshVault
does not do this for you, and does not track which versions are still in use. If you need
that number, decode the column:

```elixir
MyApp.Repo.query!("SELECT encrypted_email FROM users WHERE encrypted_email IS NOT NULL")
|> Map.fetch!(:rows)
|> Enum.map(fn [blob] ->
  {:ok, %{key_version: version}} = AshVault.Envelope.decode(blob)
  version
end)
|> Enum.frequencies()
#=> %{1 => 4210, 2 => 88_301, 3 => 12}
```

Remember that historical *backups* still reference old versions too. Destroying a key
version to tidy up the provider makes those backups partially unreadable — which may be
exactly what you want, or may be an accident. Destroying key versions is
[erasure](crypto-erasure.md), not housekeeping.

## Related

* [Crypto-erasure](crypto-erasure.md) — the irreversible one
* [Writing a rotation policy](../how-to/writing-a-rotation-policy.md)
* [Operations](operations.md) — `mix ash_vault.rotate`, `mix ash_vault.key_info`
* `AshVault.RotationPolicy`, `AshVault.Envelope.V1`
