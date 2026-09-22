//! The key cache: a bounded, TTL'd, LRU map from `(scope, slot)` to key material held
//! outside the BEAM heap.
//!
//! The security rules live in `AshVault.KeyProviders.Cached`, not here — this module
//! holds no opinion about tombstones and never decides whether a scope is destroyed. It
//! implements exactly two things that the policy layer depends on and cannot implement
//! itself:
//!
//! 1. **Eviction is a zeroing drop.** Removing an entry drops a [`SecretBuf`], which
//!    overwrites its pages before freeing them. That is the property the BEAM cannot
//!    offer at any price.
//! 2. **Eviction bumps a per-scope generation.** A `put` carrying a generation older
//!    than the scope's current one is dropped. Without this, a read that started before
//!    a `destroy` re-populates the cache after the eviction and the erased scope is
//!    readable again for a full TTL.
//!
//! ## Slot encoding
//!
//! Slots cross the NIF boundary as an `i64`, because decoding a small closed set of
//! integers cannot fail in surprising ways and needs no atom table:
//!
//! * `-1` — the current key
//! * `-2` — the tombstone
//! * `n > 0` — key version `n`
//!
//! Anything else is rejected as a bad argument.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use dashmap::DashMap;

use crate::secret::SecretBuf;

pub const SLOT_CURRENT: i64 = -1;
pub const SLOT_TOMBSTONE: i64 = -2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    Current,
    Tombstone,
    Version(u64),
}

impl Slot {
    pub fn from_i64(raw: i64) -> Option<Slot> {
        match raw {
            SLOT_CURRENT => Some(Slot::Current),
            SLOT_TOMBSTONE => Some(Slot::Tombstone),
            n if n > 0 => Some(Slot::Version(n as u64)),
            _ => None,
        }
    }

    /// Tombstones are never dropped to make room. They carry no key material, they are
    /// the fail-closed answer, and evicting one to cache a key would be backwards.
    fn evictable_for_space(&self) -> bool {
        !matches!(self, Slot::Tombstone)
    }
}

struct Entry {
    secret: Option<SecretBuf>,
    meta: Vec<u8>,
    /// Milliseconds since the cache's own epoch, or `None` for "never expires".
    expires_at: Option<u64>,
    generation: u64,
    last_used: u64,
    bytes: usize,
}

#[derive(Default)]
struct ScopeState {
    generation: u64,
    slots: std::collections::HashMap<Slot, Entry>,
}

#[derive(Default, Clone, Copy)]
struct Counters {
    entries: usize,
    bytes: usize,
}

pub struct Cache {
    scopes: DashMap<Vec<u8>, ScopeState>,
    max_entries: usize,
    max_bytes: usize,
    // Lock ordering, everywhere in this file: `counters` before any `scopes` shard.
    // Never the reverse, or two writers deadlock.
    counters: Mutex<Counters>,
    epoch: Instant,
    lru_clock: AtomicU64,
}

/// What a read found.
pub enum Fetched {
    Hit {
        secret: Vec<u8>,
        meta: Vec<u8>,
        generation: u64,
    },
    Miss {
        generation: u64,
    },
}

impl Cache {
    pub fn new(max_entries: usize, max_bytes: usize) -> Cache {
        Cache {
            scopes: DashMap::new(),
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            counters: Mutex::new(Counters::default()),
            epoch: Instant::now(),
            lru_clock: AtomicU64::new(0),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn next_tick(&self) -> u64 {
        self.lru_clock.fetch_add(1, Ordering::Relaxed)
    }

    /// The scope's current generation, `0` if it has never been evicted.
    pub fn generation(&self, scope: &[u8]) -> u64 {
        self.scopes.get(scope).map_or(0, |state| state.generation)
    }

    /// Read a slot. An expired or generation-stale entry reads as a miss.
    pub fn fetch(&self, scope: &[u8], slot: Slot) -> Fetched {
        let now = self.now_ms();
        let tick = self.next_tick();

        let Some(mut state) = self.scopes.get_mut(scope) else {
            return Fetched::Miss { generation: 0 };
        };

        let generation = state.generation;

        let Some(entry) = state.slots.get_mut(&slot) else {
            return Fetched::Miss { generation };
        };

        if entry.generation != generation || entry.expires_at.is_some_and(|at| now >= at) {
            return Fetched::Miss { generation };
        }

        entry.last_used = tick;

        Fetched::Hit {
            secret: entry
                .secret
                .as_ref()
                .map(|buf| buf.as_slice().to_vec())
                .unwrap_or_default(),
            meta: entry.meta.clone(),
            generation,
        }
    }

    /// Read a slot's key material without copying it into a returnable `Vec`.
    ///
    /// The closure runs while the shard lock is held, so it must not call back into the
    /// cache. This is how the AEAD runs against a cached key without the bytes ever
    /// becoming an Elixir term — or even leaving this module.
    pub fn with_secret<T>(
        &self,
        scope: &[u8],
        slot: Slot,
        run: impl FnOnce(&[u8]) -> T,
    ) -> Option<T> {
        let now = self.now_ms();
        let tick = self.next_tick();

        let mut state = self.scopes.get_mut(scope)?;
        let generation = state.generation;
        let entry = state.slots.get_mut(&slot)?;

        if entry.generation != generation || entry.expires_at.is_some_and(|at| now >= at) {
            return None;
        }

        entry.last_used = tick;

        entry.secret.as_ref().map(|buf| run(buf.as_slice()))
    }

    /// Write a slot, unless the scope's generation has advanced since `generation` was
    /// read. Returns `false` for a dropped (stale) write.
    pub fn put(
        &self,
        scope: &[u8],
        slot: Slot,
        secret: &[u8],
        meta: &[u8],
        ttl_ms: Option<u64>,
        generation: u64,
    ) -> bool {
        let now = self.now_ms();
        let tick = self.next_tick();

        let mut counters = self.counters.lock().expect("cache counters poisoned");

        let mut state = self.scopes.entry(scope.to_vec()).or_default();

        if state.generation != generation {
            return false;
        }

        let entry = Entry {
            secret: SecretBuf::new(secret),
            meta: meta.to_vec(),
            expires_at: ttl_ms.map(|ttl| now.saturating_add(ttl)),
            generation,
            last_used: tick,
            bytes: secret.len(),
        };

        let bytes = entry.bytes;

        match state.slots.insert(slot, entry) {
            // Replacing an entry drops the old `SecretBuf` here, zeroing it.
            Some(previous) => {
                counters.bytes = counters
                    .bytes
                    .saturating_add(bytes)
                    .saturating_sub(previous.bytes);
            }
            None => {
                counters.entries += 1;
                counters.bytes += bytes;
            }
        }

        drop(state);

        if counters.entries > self.max_entries || counters.bytes > self.max_bytes {
            self.trim(&mut counters);
        }

        true
    }

    /// Drop every entry for a scope and bump its generation. Synchronous, and every
    /// dropped entry is zeroed before this returns.
    pub fn evict_scope(&self, scope: &[u8]) {
        let mut counters = self.counters.lock().expect("cache counters poisoned");

        let mut state = self.scopes.entry(scope.to_vec()).or_default();

        let (count, bytes) = state
            .slots
            .values()
            .fold((0usize, 0usize), |(n, b), entry| (n + 1, b + entry.bytes));

        // `clear` drops every `Entry`, and each `Entry` drop zeroes its `SecretBuf`.
        // That happens inside this call, which is what makes `evict_scope/1` in Elixir a
        // synchronous erasure rather than a request to erase.
        state.slots.clear();
        state.generation += 1;

        counters.entries = counters.entries.saturating_sub(count);
        counters.bytes = counters.bytes.saturating_sub(bytes);
    }

    /// Drop everything, bumping every known scope's generation.
    pub fn evict_all(&self) {
        let mut counters = self.counters.lock().expect("cache counters poisoned");

        for mut state in self.scopes.iter_mut() {
            state.slots.clear();
            state.generation += 1;
        }

        counters.entries = 0;
        counters.bytes = 0;
    }

    pub fn stats(&self) -> (u64, u64) {
        let counters = self.counters.lock().expect("cache counters poisoned");
        (counters.entries as u64, counters.bytes as u64)
    }

    /// Drop least-recently-used entries until both bounds hold again.
    ///
    /// Called with the counters lock held, so the walk sees a consistent total.
    fn trim(&self, counters: &mut Counters) {
        let mut victims: Vec<(Vec<u8>, Slot, u64, usize)> = Vec::new();

        for state in self.scopes.iter() {
            let scope = state.key().clone();

            for (slot, entry) in state.slots.iter() {
                if slot.evictable_for_space() {
                    victims.push((scope.clone(), *slot, entry.last_used, entry.bytes));
                }
            }
        }

        victims.sort_by_key(|(_scope, _slot, last_used, _bytes)| *last_used);

        for (scope, slot, _last_used, bytes) in victims {
            if counters.entries <= self.max_entries && counters.bytes <= self.max_bytes {
                break;
            }

            if let Some(mut state) = self.scopes.get_mut(&scope) {
                if state.slots.remove(&slot).is_some() {
                    counters.entries = counters.entries.saturating_sub(1);
                    counters.bytes = counters.bytes.saturating_sub(bytes);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> Cache {
        Cache::new(1024, 1 << 20)
    }

    #[test]
    fn put_then_fetch_round_trips() {
        let cache = cache();
        assert!(cache.put(b"acme", Slot::Current, &[1u8; 32], b"meta", Some(60_000), 0));

        match cache.fetch(b"acme", Slot::Current) {
            Fetched::Hit {
                secret,
                meta,
                generation,
            } => {
                assert_eq!(secret, vec![1u8; 32]);
                assert_eq!(meta, b"meta");
                assert_eq!(generation, 0);
            }
            Fetched::Miss { .. } => panic!("expected a hit"),
        }
    }

    #[test]
    fn unknown_scope_misses_at_generation_zero() {
        let cache = cache();
        assert!(matches!(
            cache.fetch(b"nobody", Slot::Current),
            Fetched::Miss { generation: 0 }
        ));
    }

    #[test]
    fn zero_ttl_expires_immediately() {
        let cache = cache();
        cache.put(b"acme", Slot::Current, &[1u8; 32], b"", Some(0), 0);
        assert!(matches!(
            cache.fetch(b"acme", Slot::Current),
            Fetched::Miss { .. }
        ));
    }

    #[test]
    fn infinite_ttl_never_expires() {
        let cache = cache();
        cache.put(b"acme", Slot::Tombstone, b"", b"destroyed", None, 0);
        assert!(matches!(
            cache.fetch(b"acme", Slot::Tombstone),
            Fetched::Hit { .. }
        ));
    }

    #[test]
    fn evict_scope_removes_everything_and_bumps_the_generation() {
        let cache = cache();
        cache.put(b"acme", Slot::Current, &[1u8; 32], b"", Some(60_000), 0);
        cache.put(b"acme", Slot::Version(1), &[2u8; 32], b"", Some(60_000), 0);
        cache.put(b"other", Slot::Current, &[3u8; 32], b"", Some(60_000), 0);

        assert_eq!(cache.stats(), (3, 96));

        cache.evict_scope(b"acme");

        assert!(matches!(
            cache.fetch(b"acme", Slot::Current),
            Fetched::Miss { generation: 1 }
        ));
        assert!(matches!(
            cache.fetch(b"acme", Slot::Version(1)),
            Fetched::Miss { generation: 1 }
        ));
        // A sibling scope is untouched: erasure is per scope, never per table.
        assert!(matches!(
            cache.fetch(b"other", Slot::Current),
            Fetched::Hit { .. }
        ));
        assert_eq!(cache.stats(), (1, 32));
    }

    /// The race the generation fence exists for: a read misses, a `destroy` evicts, and
    /// the read's `put` arrives afterwards carrying the pre-eviction generation.
    #[test]
    fn a_stale_put_after_an_eviction_is_dropped() {
        let cache = cache();

        let Fetched::Miss { generation } = cache.fetch(b"acme", Slot::Current) else {
            panic!("expected a miss");
        };

        cache.evict_scope(b"acme");

        assert!(
            !cache.put(
                b"acme",
                Slot::Current,
                &[9u8; 32],
                b"",
                Some(60_000),
                generation
            ),
            "a put carrying a pre-eviction generation must be refused"
        );
        assert!(matches!(
            cache.fetch(b"acme", Slot::Current),
            Fetched::Miss { .. }
        ));
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn a_put_at_the_current_generation_is_accepted_after_an_eviction() {
        let cache = cache();
        cache.evict_scope(b"acme");

        let Fetched::Miss { generation } = cache.fetch(b"acme", Slot::Current) else {
            panic!("expected a miss");
        };
        assert_eq!(generation, 1);
        assert!(cache.put(
            b"acme",
            Slot::Current,
            &[9u8; 32],
            b"",
            Some(60_000),
            generation
        ));
    }

    #[test]
    fn evict_all_clears_and_bumps_every_scope() {
        let cache = cache();
        cache.put(b"a", Slot::Current, &[1u8; 32], b"", Some(60_000), 0);
        cache.put(b"b", Slot::Current, &[2u8; 32], b"", Some(60_000), 0);

        cache.evict_all();

        assert_eq!(cache.stats(), (0, 0));
        assert_eq!(cache.generation(b"a"), 1);
        assert_eq!(cache.generation(b"b"), 1);
    }

    #[test]
    fn entry_bound_drops_the_least_recently_used() {
        let cache = Cache::new(2, 1 << 20);

        cache.put(b"a", Slot::Current, &[1u8; 32], b"", Some(60_000), 0);
        cache.put(b"b", Slot::Current, &[2u8; 32], b"", Some(60_000), 0);
        // Touch "a" so "b" becomes the least recently used.
        assert!(matches!(
            cache.fetch(b"a", Slot::Current),
            Fetched::Hit { .. }
        ));
        cache.put(b"c", Slot::Current, &[3u8; 32], b"", Some(60_000), 0);

        assert_eq!(cache.stats().0, 2);
        assert!(matches!(
            cache.fetch(b"b", Slot::Current),
            Fetched::Miss { .. }
        ));
        assert!(matches!(
            cache.fetch(b"a", Slot::Current),
            Fetched::Hit { .. }
        ));
        assert!(matches!(
            cache.fetch(b"c", Slot::Current),
            Fetched::Hit { .. }
        ));
    }

    #[test]
    fn byte_bound_is_enforced_independently_of_the_entry_bound() {
        let cache = Cache::new(1000, 64);

        cache.put(b"a", Slot::Current, &[1u8; 32], b"", Some(60_000), 0);
        cache.put(b"b", Slot::Current, &[2u8; 32], b"", Some(60_000), 0);
        cache.put(b"c", Slot::Current, &[3u8; 32], b"", Some(60_000), 0);

        let (entries, bytes) = cache.stats();
        assert_eq!(entries, 2);
        assert_eq!(bytes, 64);
    }

    /// Dropping a tombstone to make room for a key would turn a fail-closed answer into
    /// a provider round trip that could fail open.
    #[test]
    fn tombstones_are_never_dropped_for_space() {
        let cache = Cache::new(1, 1 << 20);

        cache.put(b"a", Slot::Tombstone, b"", b"destroyed", None, 0);
        cache.put(b"b", Slot::Current, &[2u8; 32], b"", Some(60_000), 0);
        cache.put(b"c", Slot::Current, &[3u8; 32], b"", Some(60_000), 0);

        assert!(matches!(
            cache.fetch(b"a", Slot::Tombstone),
            Fetched::Hit { .. }
        ));
    }

    #[test]
    fn with_secret_sees_the_bytes_without_copying_them_out() {
        let cache = cache();
        cache.put(b"acme", Slot::Current, &[7u8; 32], b"", Some(60_000), 0);

        let sum = cache.with_secret(b"acme", Slot::Current, |key| {
            key.iter().map(|b| *b as u32).sum::<u32>()
        });

        assert_eq!(sum, Some(7 * 32));
        assert_eq!(cache.with_secret(b"nobody", Slot::Current, |_| ()), None);
    }

    #[test]
    fn slot_decoding_rejects_nonsense() {
        assert_eq!(Slot::from_i64(-1), Some(Slot::Current));
        assert_eq!(Slot::from_i64(-2), Some(Slot::Tombstone));
        assert_eq!(Slot::from_i64(7), Some(Slot::Version(7)));
        assert_eq!(Slot::from_i64(0), None);
        assert_eq!(Slot::from_i64(-3), None);
        assert_eq!(Slot::from_i64(i64::MIN), None);
    }

    #[test]
    fn replacing_an_entry_does_not_double_count_bytes() {
        let cache = cache();
        cache.put(b"a", Slot::Current, &[1u8; 32], b"", Some(60_000), 0);
        cache.put(b"a", Slot::Current, &[1u8; 16], b"", Some(60_000), 0);
        assert_eq!(cache.stats(), (1, 16));
    }

    #[test]
    fn concurrent_readers_and_evictions_stay_consistent() {
        use std::sync::Arc;

        let cache = Arc::new(cache());
        cache.put(b"acme", Slot::Current, &[1u8; 32], b"", Some(60_000), 0);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        let _ = cache.fetch(b"acme", Slot::Current);
                        let _ = cache.generation(b"acme");
                    }
                })
            })
            .collect();

        for _ in 0..50 {
            cache.evict_scope(b"acme");
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(cache.stats(), (0, 0));
        assert_eq!(cache.generation(b"acme"), 50);
    }
}
