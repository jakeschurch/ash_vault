# ash_vault_rustler

A Rust NIF providing an AshVault key cache and an AES-256-GCM cipher that hold key
material **outside the BEAM heap**, so that eviction can actually zero it.

Optional. The parent `ash_vault` has no Rust dependency and never will.

```elixir
def deps do
  [
    {:ash_vault, "~> 0.1"},
    {:ash_vault_rustler, "~> 0.1"}
  ]
end
```

```elixir
use AshVault.Vault,
  key_provider: MyApp.Keys,
  cache: [backend: AshVaultRustler.KeyCache, ttl: :timer.seconds(30)]
```

---

## What this buys

### The BEAM cannot zero memory, and that makes crypto-erasure eventual

AshVault's whole reason to exist is one sentence: destroying a customer's keys makes
their historical ciphertext permanently undecryptable. A key cache quietly weakens that.
"Evicting" a key from ETS drops a *reference*; the bytes survive in however many process
heaps read them, for however long the garbage collector takes, and there is no BEAM API
that overwrites them. Every BEAM crypto library shares this. Cloak does not attempt it —
zero hits for zero/wipe/scrub across its `lib/`, and it keeps every key in a named
`:protected` ETS table for the life of the process.

`AshVaultRustler.KeyCache` fixes exactly that, and only that:

| | `AshVault.KeyCaches.ETS` | `AshVaultRustler.KeyCache` |
|---|---|---|
| Eviction is synchronous | yes | yes |
| Eviction is observable (no later read can see it) | yes | yes |
| Generation fence against a racing repopulate | yes | yes |
| **Eviction overwrites the bytes** | **no** | **yes** |
| Key pages `mlock`ed out of swap | no | yes (best effort) |
| Needs a Rust toolchain or a precompiled artifact | no | yes |

Each cached key lives in a page-aligned allocation the crate owns, `mlock`ed into RAM,
and `Drop`ped with a volatile overwrite. `evict_scope/1` returns only after those writes
have happened.

### Opaque key handles

`AshVaultRustler.KeyProviders.Opaque` wraps any provider so it returns
`%AshVault.Key{}` handles instead of binaries, and `AshVaultRustler.Cipher` runs the AEAD
against a handle. The key never becomes an Elixir term during an encrypt or a decrypt.

### A cipher you can drop in without stranding a row

`AshVaultRustler.Cipher` uses the same id (`:aes_256_gcm_v1`), the same 12-byte nonce,
the same 16-byte tag and the same AAD as `AshVault.Ciphers.AES.GCM`. A value written by
either decrypts with the other; the test suite asserts both directions across sizes from
0 bytes to 200 KB.

---

## What this does **not** buy

Be precise about this, because the temptation to overclaim here is enormous.

**The level-1 cache does not eliminate the per-operation copy.**
`AshVault.KeyProviders.Cached.get_key/2` returns a *binary* to the BEAM. A copy of the
key lands on an Elixir process heap for every single encrypt and decrypt, and that copy
is the garbage collector's business, not ours. This package bounds the lifetime of the
**authoritative** copy. Eliminating the per-operation one needs the opaque-handle path,
which is a separate opt-in.

**Even the opaque path has a boundary.** The wrapped provider returns a binary — that is
its contract — so the key bytes pass through the BEAM once, on the way into the handle.
What goes away is the *repeat*: with a cache in front, key bytes exist as an Elixir term
once per cache miss rather than once per field read.

**The TTL is the erasure SLA, but only for erasures that do not go through the vault.**
`AshVault.KeyProviders.Cached.destroy/1` evicts synchronously on every connected node
before it returns, and fails if any node does not acknowledge — so an erasure performed
through the vault is immediate. An erasure performed **out of band** is not: a
`mix ash_vault.destroy_keys` in an unclustered node, an operator deleting a transit key
in OpenBao by hand, another service revoking it. None of those call `evict_scope/1`, and
the cache serves the erased scope until the entry expires. **That TTL is the number you
can write in a DPA**, and it defaults to 30 seconds.

**`mlock` is best effort, and it is charged per page.** Each cached key gets its own
page, because `mlock`/`munlock` act on whole pages and locking a 32-byte buffer inside a
shared page would unlock whatever else lives there when it is freed. So:

> A 32-byte key costs **4 KiB of locked memory**, and `:max_bytes` counts key bytes, not
> pages. The defaults (`max_entries: 1_024`, `max_bytes: 1_048_576`) can lock up to
> **4 MiB** while the reported byte total reads 32 KiB. **With this backend, size
> `:max_entries` against `RLIMIT_MEMLOCK`**, not against `:max_bytes`.

A default container `ulimit -l` is often 64 KiB — sixteen pages — so locking starts
failing after roughly sixteen cached keys on a stock host. That is not fatal: the failure
is logged once, loudly, after the first write that observes it, and caching continues,
because a key that might reach swap beats a node that refuses to decrypt. Check
`AshVaultRustler.mlock_status/0` in production and alert on a non-zero `:failed`.

**Nothing here defends against a compromised application.** An attacker with code
execution can ask the cache for a key exactly as your app does. See the parent's
[threat model](../documentation/topics/threat-model.md).

---

## The rule that matters most

> **Never cache the absence of a tombstone.**

`{:error, :destroyed}` is cached forever: destruction is monotonic, so a cached tombstone
can only be right, and caching it makes reads fail *closed* even when the provider is
unreachable. The absence of a tombstone is never cached; nor is `{:error, :not_found}`,
nor a transport failure.

Caching `{:ok, key}` is, strictly, an implicit cache of "not destroyed", and pretending
otherwise would be the fifth fail-open tombstone read in this project's history. Two
mechanisms contain it: synchronous cluster-wide eviction on the destroy path, and a short
TTL as the floor for everything else. The policy lives in
`AshVault.KeyProviders.Cached` — in Elixir, where it can be read and reviewed — and the
Rust crate holds no opinion about tombstones at all.

---

## Configuration

### The cipher: set **both** `:cipher` and `:ciphers`

This is the easiest thing to get wrong, and it is a consequence of the wire compatibility
being real:

```elixir
# governs ENCRYPTION
use AshVault.Vault, key_provider: MyApp.Keys, cipher: AshVaultRustler.Cipher

# governs DECRYPTION — required
config :ash_vault, :ciphers, %{"aes_256_gcm_v1" => AshVaultRustler.Cipher}
```

`AshVault.Vault.Runtime.decrypt!/3` resolves the cipher from the **envelope**, through
`AshVault.Cipher.registry/0`, not from the vault's `:cipher` option — deliberately, so
that values keep decrypting after the default cipher changes. Since this cipher shares
the built-in id, a vault configured with only `:cipher` will encrypt in Rust and decrypt
in Elixir. Harmless with a binary key; **impossible** with an opaque handle, which is
where you find out.

### The cache

```elixir
use AshVault.Vault,
  key_provider: MyApp.Keys,
  cache: [
    backend: AshVaultRustler.KeyCache,
    ttl: :timer.seconds(30),          # current key; also the erasure SLA
    historical_ttl: :timer.seconds(30),
    max_entries: 1_024,
    max_bytes: 1_048_576,
    cluster: true,                    # evict on every connected node, fail if any doesn't ack
    evict_timeout: 5_000
  ]
```

Then supervise the generated provider — it owns the cache:

```elixir
children = [MyApp.Vault.CachedKeyProvider]
```

If it is not started, every read goes to the provider. Slower, and correct.

### Opaque keys

```elixir
defmodule MyApp.OpaqueKeys do
  use AshVaultRustler.KeyProviders.Opaque, provider: AshVault.KeyProviders.OpenBao
end

use AshVault.Vault, key_provider: MyApp.OpaqueKeys, cipher: AshVaultRustler.Cipher
config :ash_vault, :ciphers, %{"aes_256_gcm_v1" => AshVaultRustler.Cipher}
```

A cipher that cannot take a handle raises `AshVault.Errors.OpaqueKeyUnsupported` naming
both modules. There is deliberately no fallback that unwraps the handle — that would put
the key back on the BEAM heap, silently, which is the one thing the handle prevents.

---

## Scheduler discipline, and the numbers behind it

Measured on this host (AES-NI, `mix run bench/scheduler_bench.exs`):

| plaintext | normal scheduler | dirty CPU scheduler | OTP `:crypto` |
|---:|---:|---:|---:|
| 16 B | 1.20 µs | 1.73 µs | 1.90 µs |
| 64 B | 0.68 µs | — | — |
| 1 KiB | 1.70 µs | 3.04 µs | 2.72 µs |
| 4 KiB | 3.92 µs | — | — |
| 16 KiB | 13.6 µs | — | — |
| 64 KiB | 46.4 µs | 80.9 µs | 42.0 µs |
| 256 KiB | 319 µs | — | — |
| 1 MiB | 1529 µs | 1055 µs | 715 µs |
| 4 MiB | 5958 µs | 5392 µs | — |

Cache operations: `fetch` 4.07 µs (ETS backend: 3.64 µs), `evict_scope` 0.15 µs.

**Threshold: 64 KiB.** The BEAM's guidance is ~1 ms per NIF call; on this machine that is
crossed around 700 KiB, so 64 KiB carries a ~20x margin. It is not set higher because AES
without hardware acceleration is roughly an order of magnitude slower — 64 KiB still
lands under 1 ms on such a CPU, 256 KiB would not. Dirty dispatch costs a fixed ~0.5–1 µs,
which is why the threshold is not simply zero. Every realistic encrypted column is far
below 64 KiB, so in practice AshVault field operations never pay the dispatch cost.

Cache reads are a `DashMap` lookup — sub-microsecond of actual work — and stay on a
normal scheduler unconditionally.

Override for unusual hardware:

```elixir
config :ash_vault_rustler, dirty_threshold_bytes: 262_144
```

Note the honest result in that table: **for binary keys, this cipher is not faster than
OTP's**, and at 1 MiB it is slower. Performance is not the reason to adopt it; the zeroing
cache and the opaque key path are.

---

## Safety

* **No hand-rolled crypto.** RustCrypto's `aes-gcm`, which has had a third-party audit
  (NCC Group, funded by MobileCoin) and uses AES-NI/CLMUL where available.
* **No NIF can abort the VM.** Every NIF returns a value or an error term. Rustler wraps
  each body in `catch_unwind`, so a panic becomes an error in the *calling process*;
  `test/panic_test.exs` proves that on this OTP build rather than asserting it.
* **`unsafe` appears in exactly one module** (`native/ashvault_nif/src/secret.rs`), for
  the page-aligned allocation and its zeroing drop. Every block carries a `SAFETY:`
  comment, because a bug there takes down the node rather than one process.
* **Constant-time comparison** (`subtle`) for anything whose result is a fact about key
  material.
* **Truncated tags and short nonces are refused** before the key reaches the AEAD — the
  same control, for the same stated reason, as the Elixir cipher. OTP's
  `:crypto.crypto_one_time_aead/7` accepts a truncated GCM tag and compares only its
  leading bytes, which made a ≤256-guess forgery possible through an attacker-controlled
  `tag_len` in the envelope.
* **Unauthenticated plaintext is zeroed** rather than returned when a tag check fails.

### Known coverage gap

`AshVault.KeyProviders.Cached.evict_scope/1` fans out to `Node.list(:connected)`, which is
empty on a single node, so the `:erpc.multicall/5` call itself is never executed by the
test suite — there is no cluster here to stand one up against. What *is* tested is the
decision the fan-out feeds:
`AshVault.KeyProviders.Cached.classify_evictions/2` is public and unit-tested against
every shape `:erpc` produces (`{:ok, :ok}`, `{:ok, {:error, _}}`, `{:error, {:erpc,
:noconnection}}`, `{:error, {:erpc, :timeout}}`, `{:exit, _}`, `{:throw, _}`, an
exception result, and garbage), asserting that **anything other than a positive
`{:ok, :ok}` is a failure** and therefore makes `destroy/1` return an error. The wiring
between `multicall` and that function is four lines and is not covered.

---

## Distribution

Today this package **builds from source** via `rustler`, so consumers need a Rust
toolchain and a linker.

That is a genuine adoption cost, and this repo's own host is the worst case for it: it
has `cargo` but no linker at all, which is why every build and test here runs inside
`nix develop`.

### The `rustler_precompiled` path — wired, and deliberately off

The switch exists in `AshVaultRustler.Native`. It is **off**, and the default build is
still from source, because a `base_url` pointing at a release that does not exist turns
every `mix test` in every consuming project into a NIF load failure — a far worse default
than requiring a toolchain. Nothing here can be finished on a developer machine: it needs
real published artifacts.

What is already done:

* `{:rustler_precompiled, "~> 0.8"}` is a dependency, alongside `rustler`. Neither is
  `optional:`, because `AshVaultRustler.Native` chooses between them at **compile** time
  from an environment variable, so whichever the switch picks has to already be present.
* `AshVaultRustler.Native` carries both `use` forms, the target list, and the `base_url`.
* `.github/workflows/nif-release.yml` cross-compiles every target and attaches the
  artifacts to a release, on a `ash_vault_rustler-v*` tag or on `workflow_dispatch`.
* `mix nif.checksum` generates the checksum file.

Try the precompiled code path without a release, which is as far as this can be taken
locally:

```sh
ASH_VAULT_RUSTLER_PRECOMPILED=1 ASH_VAULT_RUSTLER_BUILD=1 mix compile --force
```

`ASH_VAULT_RUSTLER_PRECOMPILED=1` takes the `RustlerPrecompiled` branch;
`ASH_VAULT_RUSTLER_BUILD=1` makes it build from source rather than download, which is
also what CI uses to produce the artifacts. Both are read at compile time, so changing
either needs `--force`.

### Releasing a precompiled NIF

For the maintainer, in order. Steps 1-3 are mechanical; **step 5 is the irreversible
one**, and it is last on purpose.

1. Set the version in `ash_vault_rustler/mix.exs`. `base_url` is built from it, so the
   tag, the version and the artifact names must agree exactly.
2. Confirm `base_url` in `AshVaultRustler.Native` names the real repository. It is
   currently `https://github.com/jakeschurch/ash_vault/releases/download/ash_vault_rustler-v#{@version}`.
   If the repository is ever moved or renamed, this is the line that silently 404s.
3. Push the tag and let the workflow finish:

   ```sh
   git tag ash_vault_rustler-v0.1.0 && git push origin ash_vault_rustler-v0.1.0
   ```

   Every matrix job must be green. A missing target is not a soft failure: a consumer on
   that target gets a download error at compile time. Run the workflow by hand first
   (`workflow_dispatch`) if there is any doubt — a bad release has to be deleted, and a
   deleted release breaks anyone who already downloaded from it.
4. Generate and **commit** the checksum file, from `ash_vault_rustler/`:

   ```sh
   mix nif.checksum
   git add checksum-Elixir.AshVaultRustler.Native.exs
   ```

   This is what makes a downloaded `.so` verifiable rather than merely convenient. It is
   not optional and it is not generated at consumer build time — without it in the
   package, `RustlerPrecompiled` refuses to use a downloaded artifact.
5. Flip the default: in `AshVaultRustler.Native`, change

   ```elixir
   @precompiled_by_default false
   ```

   to `true`. From that commit on, `ASH_VAULT_RUSTLER_BUILD=1` is the escape hatch back
   to a source build, and `ASH_VAULT_RUSTLER_PRECOMPILED` stops mattering.
6. Verify from a clean checkout on a machine **without** a Rust toolchain that
   `mix deps.get && mix compile` succeeds. That is the entire point of the exercise, and
   it is the one check that cannot be done in the repository that produced the artifacts.

Until step 5 lands, consumers build from source exactly as they do today.

---

## Building and testing

Everything needs a linker. In this repo:

```sh
nix develop --command bash -c 'cd ash_vault_rustler && mix test'
nix develop --command bash -c 'cd ash_vault_rustler/native/ashvault_nif && cargo test'
nix develop --command bash -c 'cd ash_vault_rustler/native/ashvault_nif && cargo clippy --all-targets -- -D warnings'
nix develop --command bash -c 'cd ash_vault_rustler && mix run bench/scheduler_bench.exs'
```

The Elixir suite runs the parent's own `AshVault.KeyProvider` contract cases against
`AshVault.KeyProviders.Cached` with both backends. `test/parent_support/` holds a symlink
to the parent's `key_provider_cases.ex` — the same file, not a copy, because a copied
contract suite drifts and a drifted contract suite is worse than none.
