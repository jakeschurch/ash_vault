# ash_vault_rustler — spec

A Rust NIF providing an `AshVault.Cipher` and an `AshVault.KeyCache` that hold key material
outside the BEAM heap, so that eviction can actually zero it.

## Why this exists

`documentation/topics/threat-model.md` has to admit a limitation today: the BEAM cannot
securely zero memory. Key binaries over 64 bytes are refcounted on a shared heap, "evicting"
only drops a reference, and GC timing is not ours to control. Every BEAM crypto library shares
this — Cloak does not even attempt it (verified: zero hits for zero/wipe/scrub across its
`lib/`, and it keeps every key in a named `:protected` ETS table for the life of the process).

The consequence that matters is the cache. Without this package, a cached key's lifetime after
`destroy_keys!` is "until the GC gets to it", which makes crypto-erasure eventual in an
unbounded way. With it, eviction is a `Drop` that zeroes, synchronously, before `destroy!`
returns.

## Two levels, staged. Level 1 ships first and alone if need be.

### Level 1 — the cache (no core contract change)

`AshVault.KeyProviders.Cached` wraps any other provider:

```elixir
use AshVault.Vault,
  key_provider: {AshVault.KeyProviders.Cached,
                 provider: AshVault.KeyProviders.OpenBao,
                 cache: AshVaultRustler.KeyCache,
                 ttl: :timer.minutes(5)}
```

Key material lives in a Rust `DashMap<(Scope, u32), Zeroizing<[u8; 32]>>`. `get_key/2` still
returns a binary to the BEAM — so a transient copy exists per operation — but no long-lived
copy does, and eviction zeroes the authoritative one.

**This is honest about what it buys.** It bounds the window, it does not eliminate the copy.
Say so in the moduledoc; do not claim the level-2 property here.

### Level 2 — handle-based keys (opt-in core contract extension)

Add an opaque key handle so the material never crosses the boundary:

```elixir
defmodule AshVault.Key do
  @moduledoc "An opaque handle to key material that may live outside the BEAM heap."
  @type t :: binary() | %__MODULE__{ref: reference(), owner: module()}
  defstruct [:ref, :owner]
end
```

- `KeyProvider.get_key/2` and `current_key/1` MAY return `%AshVault.Key{}` instead of a binary.
- `Cipher.encrypt/3` and `decrypt/3` MUST accept either. A cipher that cannot handle an opaque
  key returns `{:error, :opaque_key_unsupported}` and the vault raises a clear error naming the
  cipher and the provider — never a silent fallback that would defeat the purpose.
- `AshVaultRustler.Cipher` performs AES-256-GCM inside Rust against the handle, so the key
  never becomes an Elixir term.

Backward compatible: a binary key is still a valid `AshVault.Key.t()`, every existing provider
and the built-in cipher keep working untouched, and the whole 395-test suite must stay green
with no changes.

## Rust implementation

Crates: `rustler`, `zeroize` (with `Zeroizing`), `aes-gcm` **or** `ring` (never hand-rolled),
`dashmap`, and `region`/`memsec` for `mlock`.

```rust
struct KeyHandle { key: Zeroizing<[u8; 32]> }   // Drop zeroes
// held as rustler::ResourceArc<KeyHandle>; mlock'd so it cannot reach swap
```

Requirements:

- **Scheduler discipline.** Field-sized crypto stays on a normal scheduler; anything that could
  exceed ~1 ms goes to a dirty CPU scheduler. Benchmark and state the threshold chosen.
- **No panics across the boundary.** Every NIF returns a `Result`; a panic must become an
  Elixir error, never a VM abort. Any `unsafe` block gets a comment justifying it, because a
  bug there takes down the whole VM rather than one process.
- **`mlock` is best-effort.** It needs `RLIMIT_MEMLOCK` headroom; failing to lock must warn
  loudly and continue, not silently pretend.
- **Constant-time comparison** for anything comparing secrets.
- Cache bounded by entry count AND total bytes, LRU, with a TTL per entry. Two TTL classes:
  historical versions are immutable and may be cached long; the current version is
  rotation-sensitive and takes the short TTL.
- **Never cache the absence of a tombstone.** Caching `destroyed` is monotonic and fail-closed
  and may be cached freely; caching "not destroyed" would resurrect an erased tenant for the
  TTL. This asymmetry is the single most important rule in the package.
- `evict_scope/1` must be synchronous and must complete before `destroy!` returns. In a
  cluster it must evict on every node and FAIL if any node does not acknowledge — reporting
  success while a peer still holds the key is the worst available outcome.

## Distribution

`rustler_precompiled` with checksums, so consumers do not need a Rust toolchain — this repo's
own host has cargo but no linker, which is exactly the situation to design for. Build from
source must remain possible via an env var.

The parent `ash_vault` keeps zero Rust dependencies. This is a separate, optional package.

## Tests

- Round-trip against the pure-Elixir cipher: bytes encrypted by one decrypt with the other,
  proving wire compatibility in both directions.
- The full shared provider contract suite (`test/support/key_provider_cases.ex`) against
  `Cached` wrapping Memory, Local and OpenBao.
- **Eviction zeroes:** after `evict_scope/1`, assert the key is gone from the Rust side by its
  own accessor. (Proving a zero from Elixir is not possible; the test asserts the observable
  contract, and the Rust unit test asserts the buffer.)
- Destroy-then-read through a cached provider returns `KeyDestroyed`, never a cached hit.
- TTL expiry returns to the provider rather than serving stale, including during an outage.
- Concurrent access: N processes hammering one scope produce one provider fetch, not N.
- A cipher rejecting an opaque key produces the clear error, never a silent binary fallback.
- Level 2: assert `get_key/2` returns a `%AshVault.Key{}` and that no 32-byte binary matching
  the key appears in the process heap afterwards (best-effort, via `:erlang.process_info`).

## Definition of done

`cargo test` green, `cargo clippy -- -D warnings` clean, `mix test` green in the new package,
and the parent's 395 tests unchanged and still passing.
