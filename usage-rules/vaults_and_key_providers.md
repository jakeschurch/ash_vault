# Vaults and key providers

## The one rule that matters

**The key store must be a different system from the database**, and must not be in the
database's backup, snapshot or volume. If one restore brings back both keys and ciphertext,
crypto-erasure is defeated.

## Defining a vault

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault, key_provider: AshVault.KeyProviders.OpenBao
end
```

| Option | Default |
|---|---|
| `:key_provider` | required |
| `:cipher` | `AshVault.Ciphers.AES.GCM` |
| `:mac` | `AshVault.Macs.HmacSha256` (`AshVault.Macs.OpenBaoTransit` over `OpenBaoTransit`) |
| `:envelope` | `AshVault.Envelope.V1` |
| `:scope` | `AshVault.Scopes.AshTenant` (use `AshVault.Scopes.Global` if not multitenant) |
| `:rotation_policy` | `AshVault.RotationPolicies.Manual` |
| `:otp_app` | the app the vault is compiled into |
| `:cache` | `false` |

Defaults are right for almost everyone. One vault per application; resources point at it with
`vault MyApp.Vault`.

## Providers

| Provider | Use for | Notes |
|---|---|---|
| `AshVault.KeyProviders.Memory` | tests/dev only | Keys die with the process. Never production |
| `AshVault.KeyProviders.Local` | single node | Directory of key files; needs `mix ash_vault.local.init` first |
| `AshVault.KeyProviders.OpenBao` | production, multi-node | OpenBao/Vault transit; keys exported to the BEAM |
| `AshVault.KeyProviders.OpenBaoTransit` | keys must never enter the BEAM | Needs `cipher: AshVault.Ciphers.OpenBaoTransit`; slower (about 3 calls per value); **no searchable fields** |
| `AshVault.KeyProviders.Cached` | wrapper, via `cache:` | See below |

## Start and set up the provider

Do not hand-write `case` per provider; the vault answers for its provider.

```elixir
# application.ex
children = [MyApp.Repo] ++ MyApp.Vault.child_specs()

# deploy step / release command (idempotent; never on every boot)
:ok = MyApp.Vault.setup()
```

- `Local` refuses to start without an initialised root (`mix ash_vault.local.init <dir>`
  creates it with mode 0700 and a `.ash_vault_root` sentinel). That refusal protects against an
  unmounted volume looking like an empty key store. Do not "fix" it by creating the sentinel by
  hand on the wrong filesystem.
- `OpenBao` needs no process; `setup/0` mounts the KV engine that holds tombstones.

## Configuration

Per provider module, under your own OTP app (or `:ash_vault`, which your app merges over):

```elixir
config :my_app, AshVault.KeyProviders.Local, root: System.fetch_env!("ASH_VAULT_KEY_ROOT")

config :my_app, AshVault.KeyProviders.OpenBao,
  address: "http://127.0.0.1:8200",
  token: {:system, "BAO_TOKEN"},   # binary, {:system, "VAR"}, or 0-arity fun
  transit_mount: "transit",
  kv_mount: "ashvault"
```

Never commit tokens. Put them in `config/runtime.exs`.

## Key caching: leave it off

`cache: true` (or `cache: [ttl: ..., max_entries: ...]`) wraps the provider in a TTL cache.
Default is off because a cache turns erasure from immediate into "eventually, within the TTL"
for any destroy that does not go through your vault. If you enable it:

- Add the generated `MyApp.Vault.CachedKeyProvider` to supervision (`child_specs/0` already
  includes it).
- Destroy through `AshVault.destroy_keys!/3` (it evicts synchronously), never by deleting
  keys out of band.
- `cache: true` over `Memory` is refused with a warning (pointless).

## Don't

- Don't use `Memory` in production, or `Local` with the root inside the repo/DB volume.
- Don't switch providers at runtime; the vault is resolved at compile time. Two vaults
  (migration) are supported through the `fun/2` vault form on `vault`.
