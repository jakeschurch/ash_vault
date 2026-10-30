# Rules for working with AshVaultRustler

AshVaultRustler is an optional native key cache and AES-256-GCM cipher for AshVault.
Read AshVault's own usage rules before changing encrypted resources or key providers.

## Configure the cipher and registry together

```elixir
use AshVault.Vault,
  key_provider: MyApp.Keys,
  cipher: AshVaultRustler.Cipher

config :ash_vault, :ciphers, %{"aes_256_gcm_v1" => AshVaultRustler.Cipher}
```

The vault's cipher controls encryption; the envelope registry controls decryption.
Both must select the native cipher when keys are opaque handles. The native cipher
shares the built-in AES-256-GCM wire format, so existing ciphertext remains readable.
Never unwrap an opaque handle or fall back to exporting key bytes after an error.

## Cache only with an explicit erasure budget

```elixir
use AshVault.Vault,
  key_provider: MyApp.Keys,
  cache: [backend: AshVaultRustler.KeyCache, ttl: :timer.seconds(30),
          historical_ttl: :timer.seconds(30), max_entries: 1_024, cluster: true]
```

Supervise the generated provider using `MyApp.Vault.child_specs/0` and run
`MyApp.Vault.setup/0`. Keep cluster eviction enabled; failure to acknowledge erasure
must remain an error. Out-of-band erasure can leave cached keys usable until the
configured current or historical TTL expires. Never cache absence of a tombstone,
missing keys or transport failures as evidence that a scope is live.

The native cache zeroes its authoritative copy on eviction. Returning a binary still
copies key material onto the BEAM heap, where it cannot be synchronously zeroed.
For opaque handles, wrap a byte-returning provider with
`use AshVaultRustler.KeyProviders.Opaque, provider: MyApp.Keys` and use the native
cipher and registry above. Importing a key still passes through the BEAM; handles
do not eliminate that boundary or protect a compromised application.

## Size locked memory by entries

Each key occupies a page-aligned allocation, typically 4 KiB. `max_bytes` counts key
bytes, not locked pages; size `max_entries` against the process's `RLIMIT_MEMLOCK`.
`mlock` is best effort. Monitor `AshVaultRustler.mlock_status/0` and investigate a
nonzero `failed` count; do not claim that every key page is unswappable.

## Build and verify

Consumers use verified precompiled artifacts by default. Set
`ASH_VAULT_RUSTLER_BUILD=1` to build from source with a Rust and C toolchain.
Keep committed `checksum-*.exs` files in the package and regenerate checksums with
`mix nif.checksum` after a release build. Never disable checksum validation.
Run this package's tests with `ASH_VAULT_RUSTLER_BUILD=1 mix test` in the repository's
Nix development shell. Preserve the parent package's error taxonomy and never put
keys, plaintext or bearer tokens in errors, logs or telemetry.
