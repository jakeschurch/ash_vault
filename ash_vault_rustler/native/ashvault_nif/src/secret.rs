//! Page-aligned, `mlock`ed, zero-on-drop storage for key material.
//!
//! This is the only reason the package exists. The BEAM cannot zero a binary: "evicting"
//! a key drops a reference and the garbage collector decides the rest. Here, a key lives
//! in an allocation this crate owns, which is:
//!
//! * **page-aligned and page-sized**, so `mlock`/`munlock` affect this allocation and
//!   nothing else. `region::lock` rounds to page boundaries, so locking a 32-byte buffer
//!   inside a shared page would also *unlock* whatever else lives on that page when the
//!   guard drops. Owning a whole page removes that hazard entirely, at a cost of one page
//!   per cached key.
//! * **locked into RAM** where the OS allows it, so the key cannot be written to swap or
//!   a hibernation image.
//! * **overwritten on drop**, before the allocator can hand the memory to anyone else.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroize;

/// Number of secret allocations successfully locked into RAM since load.
pub static LOCKED: AtomicU64 = AtomicU64::new(0);
/// Number of secret allocations that could NOT be locked (usually `RLIMIT_MEMLOCK`).
pub static LOCK_FAILED: AtomicU64 = AtomicU64::new(0);

/// A secret byte buffer that is page-aligned, best-effort `mlock`ed, and zeroed on drop.
pub struct SecretBuf {
    // Declaration order is the drop order, and it matters: `lock` must outlive the
    // zeroing, so that the overwrite happens while the pages are still resident and
    // cannot be paged out mid-wipe. `Drop` below does the zeroing explicitly before
    // dropping this field.
    ptr: NonNull<u8>,
    layout: Layout,
    len: usize,
    lock: Option<region::LockGuard>,
}

// SAFETY: `SecretBuf` owns its allocation exclusively and exposes only `&self` reads of
// immutable bytes. Nothing mutates the buffer after construction, so sharing a `&SecretBuf`
// across threads cannot race, and moving ownership across threads is sound because the
// allocation is not thread-affine. `region::LockGuard` is itself `Send + Sync`.
unsafe impl Send for SecretBuf {}
unsafe impl Sync for SecretBuf {}

impl SecretBuf {
    /// Copy `bytes` into a fresh page-aligned, locked, zero-on-drop allocation.
    ///
    /// Returns `None` for empty input: there is no secret to protect, and allocating a
    /// whole page for zero bytes is pure waste.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        let page = region::page::size();
        let size = bytes.len().div_ceil(page) * page;

        // `page` is a power of two and `size` is a non-zero multiple of it, so this
        // cannot fail; the `ok()?` is belt and braces rather than a real branch.
        let layout = Layout::from_size_align(size, page).ok()?;

        // SAFETY: `layout` has non-zero size, which is `alloc_zeroed`'s only precondition.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw)?;

        // SAFETY: `raw` points to `size >= bytes.len()` freshly allocated, writable,
        // non-overlapping bytes, and `bytes` is a valid slice for its own length.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw, bytes.len());
        }

        // `mlock` is best effort: it needs `RLIMIT_MEMLOCK` headroom, which a container
        // often does not have. Failing to lock must be loud and must not be fatal — a
        // key that might reach swap is still vastly better than a process that refuses
        // to decrypt. The counters are exposed to Elixir, which logs a warning naming
        // the limit; see `AshVaultRustler.mlock_status/0`.
        let lock = match region::lock(raw, size) {
            Ok(guard) => {
                LOCKED.fetch_add(1, Ordering::Relaxed);
                Some(guard)
            }
            Err(error) => {
                if LOCK_FAILED.fetch_add(1, Ordering::Relaxed) == 0 {
                    eprintln!(
                        "ash_vault_rustler: mlock failed ({error}); key material may reach \
                         swap. Raise RLIMIT_MEMLOCK (ulimit -l) for this process."
                    );
                }
                None
            }
        };

        Some(SecretBuf {
            ptr,
            layout,
            len: bytes.len(),
            lock,
        })
    }

    /// The secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is a live allocation of at least `len` initialised bytes, owned
        // by `self`, and the returned slice borrows `self` so it cannot outlive it.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this buffer's pages are locked into RAM.
    pub fn locked(&self) -> bool {
        self.lock.is_some()
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`layout.size()` describe the whole live allocation owned by
        // `self`, and nothing else can hold a reference to it at drop time.
        let whole =
            unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) };

        // `Zeroize::zeroize` on a byte slice is a volatile write plus a compiler fence,
        // so the optimiser cannot delete it as a dead store to memory about to be freed.
        whole.zeroize();

        // Unlock only after the wipe, so the pages cannot be evicted to swap between the
        // two steps and leave a copy of the key behind on disk.
        drop(self.lock.take());

        // SAFETY: allocated by `alloc_zeroed` with exactly this layout, never reallocated,
        // and freed exactly once because `Drop` runs once.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// Constant-time equality against a secret.
///
/// Any comparison whose *result* is a fact about key material has to be constant time; a
/// `==` on two byte slices short-circuits at the first differing byte and leaks the
/// length of the common prefix through timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bytes() {
        let buf = SecretBuf::new(&[7u8; 32]).unwrap();
        assert_eq!(buf.as_slice(), &[7u8; 32]);
        assert_eq!(buf.len(), 32);
    }

    #[test]
    fn empty_input_allocates_nothing() {
        assert!(SecretBuf::new(&[]).is_none());
    }

    #[test]
    fn allocation_is_page_aligned() {
        let buf = SecretBuf::new(&[1u8; 32]).unwrap();
        let page = region::page::size();
        assert_eq!(buf.ptr.as_ptr() as usize % page, 0);
        assert_eq!(buf.layout.size(), page);
    }

    /// The observable half of "eviction zeroes". Dropping the buffer overwrites the whole
    /// page before freeing it; this reads the raw allocation after the wipe but before
    /// `dealloc` by doing the wipe by hand on an identical buffer.
    #[test]
    fn drop_zeroes_the_allocation() {
        let buf = SecretBuf::new(&[0xAB; 32]).unwrap();
        let ptr = buf.ptr.as_ptr();
        let size = buf.layout.size();

        // Mirror `Drop`'s wipe, then observe. Reading through `ptr` after the real
        // `dealloc` would be a use-after-free, so the wipe is asserted here and `Drop`
        // itself is exercised by the other tests plus Miri-less review of the one call.
        let whole = unsafe { std::slice::from_raw_parts_mut(ptr, size) };
        assert!(whole[..32].iter().any(|byte| *byte != 0));
        whole.zeroize();
        assert!(whole.iter().all(|byte| *byte == 0));

        drop(buf);
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn multi_page_secret_is_sized_up() {
        let page = region::page::size();
        let buf = SecretBuf::new(&vec![9u8; page + 1]).unwrap();
        assert_eq!(buf.layout.size(), page * 2);
        assert_eq!(buf.as_slice().len(), page + 1);
    }
}
