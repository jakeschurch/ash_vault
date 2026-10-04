# Testing code that uses AshVault

## Use the Memory provider

`AshVault.KeyProviders.Memory` keeps keys in a process: no setup, no disk, no network. Never
use it outside dev/test.

AshVault does not start it for you. A vault always talks to the **default-named** instance, so
start it under its own name, in `async: false` tests only (the global name collides across
async tests):

```elixir
# a test module or a test/support case template
setup do
  start_supervised!({AshVault.KeyProviders.Memory, name: AshVault.KeyProviders.Memory})
  :ok
end
```

The vault's provider is fixed at compile time. To use `Memory` in test and a real provider
elsewhere, pick it in the vault module (this is an application pattern, not an AshVault
option):

```elixir
defmodule MyApp.Vault do
  use AshVault.Vault,
    key_provider: Application.compile_env(:my_app, :key_provider, AshVault.KeyProviders.OpenBao)
end

# config/test.exs
config :my_app, :key_provider, AshVault.KeyProviders.Memory
```

Or start it in your supervision tree behind a runtime flag (not `Mix.env/0`; Mix is not in
releases) for dev and test. If your tree already has `MyApp.Vault.child_specs()` and the vault
uses `Memory`, it is already running: do not `start_supervised!` it again (`already_started`).

## Always pass a tenant

Default scope is the tenant, so every action in a test needs one, including reads and lookups:

```elixir
tenant = Ash.UUID.generate()   # unique per test: scopes share one Memory provider
user = Ash.create!(User, %{email: "a@b.com"}, tenant: tenant)
assert Ash.get!(User, user.id, tenant: tenant, load: [:email]).email == "a@b.com"
```

Use a fresh tenant per test; keys are minted on first write and live as long as the provider
process.

## What to assert

- Round trip: write, then read with `load: [:email]` (or `decrypt_by_default`).
- Ciphertext at rest: query the raw column (`encrypted_email`) and assert it starts with
  `<<"AV", 1::8, _::binary>>` and does not contain the plaintext.
- Erasure: `AshVault.destroy_keys!(MyApp.Vault, tenant)`, then assert the read returns an
  `Ash.Error.Invalid` whose `errors` include `%AshVault.Errors.KeyDestroyed{}`. Do not assert
  on `CiphertextIntegrityFailed` or on an empty result.
- Missing tenant: assert an error, not "no rows": `AshVault.Errors.MissingScope` from
  `filter_by/4` or `:by_<field>`; an Ash-multitenant resource fails Ash's tenant check first.
- Lookups: `AshVault.Query.filter_by/4` or the `:by_<field>` action with `tenant:`.
- Rotation: `AshVault.rotate_key!(MyApp.Vault, tenant)` then confirm old rows still decrypt.

## Pitfalls

- A Memory provider that is not started yields `AshVault.Errors.ProviderUnavailable`, not a
  crash. Do not "fix" it by rescuing the error; start the provider.
- Keys die with the process. Do not assert persistence across restarts with Memory; use
  `Local` for that.
- Destroyed scopes are tombstoned for the life of the provider process. Use a new tenant, not
  the same one, after a destroy test.
- A `searchable?` field's `normalize:` applies on write: assert the normalized value comes back.
- Never print or `inspect` decrypted values in test failures you ship to CI logs.
