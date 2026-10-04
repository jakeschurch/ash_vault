# Rotation and erasure

Three operations people confuse:

| Operation | Effect | Reversible |
|---|---|---|
| Rotation | New key version; old rows keep decrypting untouched | n/a |
| Re-encryption | Rows rewritten under the current key version | n/a |
| Erasure | Every key version destroyed, scope tombstoned | **No** |

## Rotation

```elixir
{:ok, 3} = AshVault.rotate_key!(MyApp.Vault, "acme")             # scope key, a binary
{:ok, 2} = AshVault.rotate_key!(MyApp.Vault, "acme", nil, purpose: :mac)
```

```bash
mix ash_vault.rotate MyApp.Accounts.User --tenant acme
mix ash_vault.rotate MyApp.Accounts.User --all-tenants MyApp.Accounts.list_tenant_ids/0 --yes
mix ash_vault.key_info MyApp.Accounts.User --tenant acme   # read-only; never mints keys
```

- Rotation touches no rows. Do not follow it with a re-save "to apply it".
- It does not protect already-written data. A known-compromised key needs **re-encryption**
  (re-save rows passing the encrypted fields explicitly, e.g. `%{email: user.email}`; an
  update that omits the field leaves its ciphertext alone). There is no `reencrypt` mix task.
- It does not change searchable-field tokens.
- Rotating a destroyed scope is an error. It never re-mints.
- Prefer a scheduled `mix ash_vault.rotate` over a rotation policy; the default
  `AshVault.RotationPolicies.Manual` never rotates on its own.
- `--all-tenants` takes `Module.function/0` returning a list of tenants. `--domain` is
  inferred from `:ash_domains` when omitted.

## Erasure

```elixir
:ok = AshVault.destroy_keys!(MyApp.Vault, "acme")
```

```bash
mix ash_vault.destroy_keys MyApp.Accounts.User --tenant acme
```

- It destroys the data, MAC and lookup keys for the scope and writes a **tombstone**; the
  scope can never be re-minted. Restoring a database backup does not undo it.
- The mix task makes you type the scope back; `--yes` does not skip that and there is no
  `--force`. In `MIX_ENV=prod` it also refuses unless `MIX_ENV` was set explicitly or
  `--i-know-what-this-does` is given. Do not script around this.
- Afterwards, reads return `AshVault.Errors.KeyDestroyed`. The rows remain, as noise.
- Erasure does not touch plaintext you copied elsewhere (logs, warehouses, caches, search
  indexes, third parties). Inventory those first.
- It does not defeat a **key backup**: a copy of the key store from before the destroy
  resurrects the data. Your key-backup retention is the real lifetime of a destroyed key.

## `key_lifecycle` actions (from your app, with policies)

```elixir
defmodule MyApp.Accounts.Organization do
  use Ash.Resource, extensions: [AshVault], authorizers: [Ash.Policy.Authorizer], ...

  ash_vault do
    vault MyApp.Vault
    scope :tenant
    scope_owner? true

    key_lifecycle do
      rotate :rotate_key
      destroy :destroy_keys
    end
  end

  policies do
    policy action([:rotate_key, :destroy_keys]) do
      authorize_if actor_attribute_equals(:role, :platform_admin)
    end
  end
end

MyApp.Accounts.Organization
|> Ash.ActionInput.for_action(:destroy_keys, %{}, tenant: org_id, actor: admin)
|> Ash.run_action!()
#=> %AshVault.Erasure{scope: "…", destroyed_at: ~U[…]}
```

- Only on a `scope_owner? true` resource (the tenant/org), otherwise a compile error.
- `:destroy_keys` is as dangerous as you make it. **Always** put a policy on it.
- The action's tenant is the scope. Pass `tenant:`.

## Telling erasure from failure

- `KeyDestroyed` = erased on purpose. `ProviderUnavailable` = retry/alert. Never map the
  second to the first. Tombstone reads fail closed: an unreadable or ambiguous tombstone is
  `ProviderUnavailable` (or `ProviderForbidden` when the read is refused with `403`), never
  "not destroyed". `ProviderForbidden` = fix the policy/token/address; do not retry.
- `CiphertextIntegrityFailed` means tampered bytes, a different tenant/resource/field than
  the row was written for, or a different key. Investigate; it is never "access denied".

## Don't

- Don't pass anything but the binary scope key to these calls; it is the stringified
  tenant (`AshVault.Scopes.AshTenant` stringifies ids/atoms/integers). Use the same string
  the app encrypts under, or you act on a different scope.
- Don't call `destroy_keys!` from tests that share a Memory provider across tests without
  unique tenants.
- Don't run rotation or erasure for a `scope :global` resource without understanding it is
  application-wide.
