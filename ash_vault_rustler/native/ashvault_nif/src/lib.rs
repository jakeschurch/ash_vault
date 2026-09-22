//! NIF surface for `ash_vault_rustler`.
//!
//! ## Rules this file exists to keep
//!
//! * **No NIF may abort the VM.** Every function here returns a `Result` or a term, and
//!   never calls `panic!`, `unwrap()` on caller input, or indexes a slice by an unchecked
//!   length. Rustler wraps each call in `catch_unwind` and turns a panic into a raised
//!   `nif_panicked` in the *calling process* rather than a VM abort, which is the second
//!   line of defence, not the first. `panic_for_test/0` exists so a test can prove that
//!   second line still works on this build of OTP.
//! * **No blocking work on a normal scheduler.** Everything here is a hash lookup or a
//!   field-sized AEAD; both are microseconds. The `*_dirty` variants exist for payloads
//!   large enough to approach the BEAM's 1 ms budget, and `AshVaultRustler.Cipher` picks
//!   between them by size. See the README for the measurements behind the threshold.
//! * **Every `unsafe` block is justified in a comment.** There are exactly two places in
//!   this crate that need one — `secret.rs`'s allocation and its drop — because a bug
//!   there takes down the whole node rather than one process.
//!
//! ## What is deliberately *not* here
//!
//! No tombstone logic, no TTL policy, no decision about whether a scope is destroyed.
//! Those live in `AshVault.KeyProviders.Cached`, in Elixir, where they can be read and
//! reviewed by the people who care about them most.

mod cache;
mod crypto;
mod secret;

use std::sync::atomic::Ordering;

use rustler::types::binary::{Binary, NewBinary};
use rustler::{Atom, Encoder, Env, Error, NifResult, Resource, ResourceArc, Term};

use cache::{Cache, Fetched, Slot};
use crypto::CryptoError;
use secret::SecretBuf;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        miss,
        stale,
        auth_failed,
        invalid_key_size,
        invalid_nonce_size,
        invalid_tag_size,
        random_failed,
        invalid_slot,
        deliberate_test_panic,
    }
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// A cache instance. Held by an Elixir `GenServer` in `:persistent_term`, so the read
/// path needs neither a message nor a lock on the Elixir side.
pub struct CacheResource(Cache);

#[rustler::resource_impl]
impl Resource for CacheResource {}

// `DashMap`'s sharded `RwLock` is not `RefUnwindSafe`, which rustler's `NifReturnable`
// blanket impl requires in order to catch a panic while encoding a return value. The
// assertion is sound here because no code path in `cache.rs` can leave the map in a
// half-updated state across an unwind: every mutation is a single `insert`/`remove`/
// `clear` under one lock, and every counter update uses saturating arithmetic so it
// cannot panic on overflow in the first place.
impl std::panic::RefUnwindSafe for CacheResource {}
impl std::panic::UnwindSafe for CacheResource {}

/// An opaque handle to one key, the `:ref` inside an `%AshVault.Key{}`.
///
/// The bytes are in a page-aligned, `mlock`ed allocation that is overwritten when the
/// BEAM garbage-collects the last reference to this resource. They never become an
/// Elixir term.
pub struct KeyHandle(SecretBuf);

#[rustler::resource_impl]
impl Resource for KeyHandle {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary<'a>(env: Env<'a>, data: &[u8]) -> Term<'a> {
    let mut new = NewBinary::new(env, data.len());
    new.as_mut_slice().copy_from_slice(data);
    Binary::from(new).to_term(env)
}

fn crypto_atom(error: CryptoError) -> Atom {
    match error {
        CryptoError::InvalidKeySize => atoms::invalid_key_size(),
        CryptoError::InvalidNonceSize => atoms::invalid_nonce_size(),
        CryptoError::InvalidTagSize => atoms::invalid_tag_size(),
        CryptoError::AuthFailed => atoms::auth_failed(),
        CryptoError::RandomFailed => atoms::random_failed(),
    }
}

fn slot(raw: i64) -> NifResult<Slot> {
    Slot::from_i64(raw).ok_or_else(|| Error::Term(Box::new(atoms::invalid_slot())))
}

fn ttl(raw: i64) -> Option<u64> {
    // Negative means `:infinity`, which is only ever used for a tombstone.
    if raw < 0 {
        None
    } else {
        Some(raw as u64)
    }
}

// ---------------------------------------------------------------------------
// Cache NIFs
// ---------------------------------------------------------------------------

#[rustler::nif]
fn cache_new(max_entries: u64, max_bytes: u64) -> ResourceArc<CacheResource> {
    ResourceArc::new(CacheResource(Cache::new(
        max_entries as usize,
        max_bytes as usize,
    )))
}

#[rustler::nif]
fn cache_fetch<'a>(
    env: Env<'a>,
    cache: ResourceArc<CacheResource>,
    scope: Binary<'a>,
    slot_raw: i64,
) -> NifResult<Term<'a>> {
    let slot = slot(slot_raw)?;

    Ok(match cache.0.fetch(scope.as_slice(), slot) {
        Fetched::Hit {
            secret,
            meta,
            generation,
        } => (
            atoms::ok(),
            binary(env, &secret),
            binary(env, &meta),
            generation,
        )
            .encode(env),
        Fetched::Miss { generation } => (atoms::miss(), generation).encode(env),
    })
}

#[rustler::nif]
#[allow(clippy::too_many_arguments)]
fn cache_put(
    cache: ResourceArc<CacheResource>,
    scope: Binary<'_>,
    slot_raw: i64,
    secret: Binary<'_>,
    meta: Binary<'_>,
    ttl_ms: i64,
    generation: u64,
) -> NifResult<Atom> {
    let slot = slot(slot_raw)?;

    let written = cache.0.put(
        scope.as_slice(),
        slot,
        secret.as_slice(),
        meta.as_slice(),
        ttl(ttl_ms),
        generation,
    );

    Ok(if written { atoms::ok() } else { atoms::stale() })
}

#[rustler::nif]
fn cache_evict_scope(cache: ResourceArc<CacheResource>, scope: Binary<'_>) -> Atom {
    cache.0.evict_scope(scope.as_slice());
    atoms::ok()
}

#[rustler::nif]
fn cache_evict_all(cache: ResourceArc<CacheResource>) -> Atom {
    cache.0.evict_all();
    atoms::ok()
}

#[rustler::nif]
fn cache_stats(cache: ResourceArc<CacheResource>) -> (u64, u64) {
    cache.0.stats()
}

#[rustler::nif]
fn cache_generation(cache: ResourceArc<CacheResource>, scope: Binary<'_>) -> u64 {
    cache.0.generation(scope.as_slice())
}

/// Hand out an opaque handle to a cached key, for the level-2 path.
///
/// The key bytes are copied from the cache's allocation into the handle's own
/// `mlock`ed, zero-on-drop allocation. That copy is native-to-native: the bytes still
/// never become an Elixir term, which is the property that matters.
#[rustler::nif]
fn cache_key_handle<'a>(
    env: Env<'a>,
    cache: ResourceArc<CacheResource>,
    scope: Binary<'a>,
    slot_raw: i64,
) -> NifResult<Term<'a>> {
    let slot = slot(slot_raw)?;

    let handle = cache.0.with_secret(scope.as_slice(), slot, SecretBuf::new);

    Ok(match handle {
        Some(Some(buf)) => (atoms::ok(), ResourceArc::new(KeyHandle(buf))).encode(env),
        _ => atoms::miss().encode(env),
    })
}

// ---------------------------------------------------------------------------
// Key handle NIFs
// ---------------------------------------------------------------------------

#[rustler::nif]
fn key_handle_new(key: Binary<'_>) -> NifResult<ResourceArc<KeyHandle>> {
    if key.len() != crypto::KEY_BYTES {
        return Err(Error::Term(Box::new(atoms::invalid_key_size())));
    }

    SecretBuf::new(key.as_slice())
        .map(|buf| ResourceArc::new(KeyHandle(buf)))
        .ok_or_else(|| Error::Term(Box::new(atoms::invalid_key_size())))
}

#[rustler::nif]
fn key_handle_byte_size(handle: ResourceArc<KeyHandle>) -> u64 {
    handle.0.len() as u64
}

#[rustler::nif]
fn key_handle_mlocked(handle: ResourceArc<KeyHandle>) -> bool {
    handle.0.locked()
}

/// Constant-time comparison of a handle against candidate bytes.
///
/// The *result* of this comparison is a fact about key material, so a short-circuiting
/// `==` would leak the length of the matching prefix through timing.
#[rustler::nif]
fn key_handle_matches(handle: ResourceArc<KeyHandle>, candidate: Binary<'_>) -> bool {
    secret::constant_time_eq(handle.0.as_slice(), candidate.as_slice())
}

/// `(locked, failed)` counts for `mlock` since the NIF was loaded.
#[rustler::nif]
fn mlock_status() -> (u64, u64) {
    (
        secret::LOCKED.load(Ordering::Relaxed),
        secret::LOCK_FAILED.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------------
// Cipher NIFs
// ---------------------------------------------------------------------------

fn do_encrypt<'a>(env: Env<'a>, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Term<'a> {
    match crypto::encrypt(key, plaintext, aad) {
        Ok((ciphertext, nonce, tag)) => (
            atoms::ok(),
            (
                binary(env, &ciphertext),
                binary(env, &nonce),
                binary(env, &tag),
            ),
        )
            .encode(env),
        Err(error) => (atoms::error(), crypto_atom(error)).encode(env),
    }
}

fn do_decrypt<'a>(
    env: Env<'a>,
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Term<'a> {
    match crypto::decrypt(key, ciphertext, nonce, tag, aad) {
        Ok(plaintext) => (atoms::ok(), binary(env, &plaintext)).encode(env),
        Err(error) => (atoms::error(), crypto_atom(error)).encode(env),
    }
}

#[rustler::nif]
fn encrypt<'a>(env: Env<'a>, key: Binary<'a>, plaintext: Binary<'a>, aad: Binary<'a>) -> Term<'a> {
    do_encrypt(env, key.as_slice(), plaintext.as_slice(), aad.as_slice())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn encrypt_dirty<'a>(
    env: Env<'a>,
    key: Binary<'a>,
    plaintext: Binary<'a>,
    aad: Binary<'a>,
) -> Term<'a> {
    do_encrypt(env, key.as_slice(), plaintext.as_slice(), aad.as_slice())
}

#[rustler::nif]
fn decrypt<'a>(
    env: Env<'a>,
    key: Binary<'a>,
    ciphertext: Binary<'a>,
    nonce: Binary<'a>,
    tag: Binary<'a>,
    aad: Binary<'a>,
) -> Term<'a> {
    do_decrypt(
        env,
        key.as_slice(),
        ciphertext.as_slice(),
        nonce.as_slice(),
        tag.as_slice(),
        aad.as_slice(),
    )
}

#[rustler::nif(schedule = "DirtyCpu")]
fn decrypt_dirty<'a>(
    env: Env<'a>,
    key: Binary<'a>,
    ciphertext: Binary<'a>,
    nonce: Binary<'a>,
    tag: Binary<'a>,
    aad: Binary<'a>,
) -> Term<'a> {
    do_decrypt(
        env,
        key.as_slice(),
        ciphertext.as_slice(),
        nonce.as_slice(),
        tag.as_slice(),
        aad.as_slice(),
    )
}

/// Encrypt against an opaque handle. The key never becomes an Elixir term.
#[rustler::nif]
fn encrypt_handle<'a>(
    env: Env<'a>,
    handle: ResourceArc<KeyHandle>,
    plaintext: Binary<'a>,
    aad: Binary<'a>,
) -> Term<'a> {
    do_encrypt(
        env,
        handle.0.as_slice(),
        plaintext.as_slice(),
        aad.as_slice(),
    )
}

#[rustler::nif(schedule = "DirtyCpu")]
fn encrypt_handle_dirty<'a>(
    env: Env<'a>,
    handle: ResourceArc<KeyHandle>,
    plaintext: Binary<'a>,
    aad: Binary<'a>,
) -> Term<'a> {
    do_encrypt(
        env,
        handle.0.as_slice(),
        plaintext.as_slice(),
        aad.as_slice(),
    )
}

/// Decrypt against an opaque handle. The key never becomes an Elixir term.
#[rustler::nif]
fn decrypt_handle<'a>(
    env: Env<'a>,
    handle: ResourceArc<KeyHandle>,
    ciphertext: Binary<'a>,
    nonce: Binary<'a>,
    tag: Binary<'a>,
    aad: Binary<'a>,
) -> Term<'a> {
    do_decrypt(
        env,
        handle.0.as_slice(),
        ciphertext.as_slice(),
        nonce.as_slice(),
        tag.as_slice(),
        aad.as_slice(),
    )
}

#[rustler::nif(schedule = "DirtyCpu")]
fn decrypt_handle_dirty<'a>(
    env: Env<'a>,
    handle: ResourceArc<KeyHandle>,
    ciphertext: Binary<'a>,
    nonce: Binary<'a>,
    tag: Binary<'a>,
    aad: Binary<'a>,
) -> Term<'a> {
    do_decrypt(
        env,
        handle.0.as_slice(),
        ciphertext.as_slice(),
        nonce.as_slice(),
        tag.as_slice(),
        aad.as_slice(),
    )
}

/// Encrypt against a key that is already in the cache, without materialising it anywhere.
///
/// Returns `:miss` if the slot is not cached, which sends the caller back to the provider.
#[rustler::nif]
fn encrypt_cached<'a>(
    env: Env<'a>,
    cache: ResourceArc<CacheResource>,
    scope: Binary<'a>,
    slot_raw: i64,
    plaintext: Binary<'a>,
    aad: Binary<'a>,
) -> NifResult<Term<'a>> {
    let slot = slot(slot_raw)?;

    let result = cache.0.with_secret(scope.as_slice(), slot, |key| {
        crypto::encrypt(key, plaintext.as_slice(), aad.as_slice())
    });

    Ok(match result {
        None => atoms::miss().encode(env),
        Some(Ok((ciphertext, nonce, tag))) => (
            atoms::ok(),
            (
                binary(env, &ciphertext),
                binary(env, &nonce),
                binary(env, &tag),
            ),
        )
            .encode(env),
        Some(Err(error)) => (atoms::error(), crypto_atom(error)).encode(env),
    })
}

/// Decrypt against a key that is already in the cache.
#[rustler::nif]
#[allow(clippy::too_many_arguments)]
fn decrypt_cached<'a>(
    env: Env<'a>,
    cache: ResourceArc<CacheResource>,
    scope: Binary<'a>,
    slot_raw: i64,
    ciphertext: Binary<'a>,
    nonce: Binary<'a>,
    tag: Binary<'a>,
    aad: Binary<'a>,
) -> NifResult<Term<'a>> {
    let slot = slot(slot_raw)?;

    let result = cache.0.with_secret(scope.as_slice(), slot, |key| {
        crypto::decrypt(
            key,
            ciphertext.as_slice(),
            nonce.as_slice(),
            tag.as_slice(),
            aad.as_slice(),
        )
    });

    Ok(match result {
        None => atoms::miss().encode(env),
        Some(Ok(plaintext)) => (atoms::ok(), binary(env, &plaintext)).encode(env),
        Some(Err(error)) => (atoms::error(), crypto_atom(error)).encode(env),
    })
}

// ---------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------

/// Panic on purpose, so a test can assert that a panic inside a NIF raises in the calling
/// process and leaves the node running, rather than aborting the VM.
///
/// This is the only `panic!` in the crate and it is unreachable unless called by name.
#[rustler::nif]
fn panic_for_test() -> Atom {
    panic!("deliberate test panic from ash_vault_rustler");
}

#[rustler::nif]
fn deliberate_test_panic_atom() -> Atom {
    atoms::deliberate_test_panic()
}

rustler::init!("Elixir.AshVaultRustler.Native");
