//! AES-256-GCM, wire-compatible with `AshVault.Ciphers.AES.GCM`.
//!
//! No primitive is implemented here. The AEAD is RustCrypto's `aes-gcm`, which has had a
//! third-party audit and uses AES-NI/CLMUL where the CPU offers them.
//!
//! Wire compatibility means byte-for-byte interchangeable with the Elixir cipher:
//! a 32-byte key, a fresh 12-byte random nonce per encryption, a detached 16-byte tag,
//! and the AAD bound exactly as `AshVault.Vault.Runtime.build_aad/2` builds it. A value
//! encrypted by either side decrypts with the other.
//!
//! The length checks are copied deliberately, including the reasoning. OTP's
//! `:crypto.crypto_one_time_aead/7` accepts a truncated GCM tag and compares only its
//! leading bytes, which was a real forgery vector in this project (REVIEW_FINDINGS #6).
//! `aes-gcm`'s fixed-size `Tag` type would reject a short tag anyway, but the check is
//! written out so that the two implementations reject exactly the same inputs for exactly
//! the same reasons, rather than by accident of a different library's typing.

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aes::cipher::consts::{U12, U16};
use aes_gcm::{AeadInOut, Aes256Gcm, Key, KeyInit, Nonce, Tag};

type GcmNonce = Nonce<U12>;
type GcmTag = Tag<U16>;

/// A detached AEAD result: `(ciphertext, nonce, tag)`, the shape the AshVault envelope
/// stores.
pub type Sealed = (Vec<u8>, [u8; NONCE_BYTES], [u8; TAG_BYTES]);

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CryptoError {
    /// The key is not exactly 32 bytes. A configuration fault, never tampering.
    InvalidKeySize,
    /// The nonce is not exactly 12 bytes.
    InvalidNonceSize,
    /// The tag is not exactly 16 bytes.
    InvalidTagSize,
    /// The tag did not verify, or the AAD did not match.
    AuthFailed,
    /// The OS random source failed.
    RandomFailed,
}

/// Encrypt with a freshly generated random nonce.
///
/// Returns `(ciphertext, nonce, tag)` detached, matching the AshVault envelope's shape.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
    if key.len() != KEY_BYTES {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut nonce_bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomFailed)?;

    encrypt_with_nonce(key, plaintext, aad, nonce_bytes)
}

/// Encrypt with a caller-supplied nonce. Test-only in spirit: a nonce reused under the
/// same key destroys GCM's security completely, so production callers use `encrypt`.
pub fn encrypt_with_nonce(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    nonce_bytes: [u8; NONCE_BYTES],
) -> Result<Sealed, CryptoError> {
    if key.len() != KEY_BYTES {
        return Err(CryptoError::InvalidKeySize);
    }

    let key = Key::<Aes256Gcm>::try_from(key).map_err(|_| CryptoError::InvalidKeySize)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = GcmNonce::from(nonce_bytes);

    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, InOutBuf::from(buffer.as_mut_slice()))
        .map_err(|_| CryptoError::AuthFailed)?;

    let mut tag_bytes = [0u8; TAG_BYTES];
    tag_bytes.copy_from_slice(tag.as_slice());

    Ok((buffer, nonce_bytes, tag_bytes))
}

/// Decrypt a detached `(ciphertext, nonce, tag)`, verifying against `aad`.
pub fn decrypt(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_BYTES {
        return Err(CryptoError::InvalidKeySize);
    }

    // A short nonce is not a GCM nonce: GCM derives J0 by GHASHing anything that is not
    // 96 bits, so a 1-byte nonce is a perfectly valid input to the primitive and silently
    // widens the space an attacker controls. Only 12 bytes is ours.
    if nonce.len() != NONCE_BYTES {
        return Err(CryptoError::InvalidNonceSize);
    }

    // A truncated tag is what kept the forgery bound at 2^-8 instead of 2^-128.
    if tag.len() != TAG_BYTES {
        return Err(CryptoError::InvalidTagSize);
    }

    let key = Key::<Aes256Gcm>::try_from(key).map_err(|_| CryptoError::InvalidKeySize)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = GcmNonce::try_from(nonce).map_err(|_| CryptoError::InvalidNonceSize)?;
    let tag = GcmTag::try_from(tag).map_err(|_| CryptoError::InvalidTagSize)?;

    let mut buffer = ciphertext.to_vec();

    match cipher.decrypt_inout_detached(&nonce, aad, InOutBuf::from(buffer.as_mut_slice()), &tag) {
        Ok(()) => Ok(buffer),
        Err(_) => {
            // The library leaves the buffer holding whatever the CTR keystream produced
            // before the tag check failed. Unauthenticated plaintext must never leave
            // this function, and must not linger in a freed allocation either.
            use zeroize::Zeroize;
            buffer.zeroize();
            Err(CryptoError::AuthFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x2b; 32];

    #[test]
    fn round_trips() {
        let (ct, nonce, tag) = encrypt(&KEY, b"attack at dawn", b"aad").unwrap();
        assert_eq!(nonce.len(), 12);
        assert_eq!(tag.len(), 16);
        assert_eq!(ct.len(), b"attack at dawn".len());

        let pt = decrypt(&KEY, &ct, &nonce, &tag, b"aad").unwrap();
        assert_eq!(pt, b"attack at dawn");
    }

    #[test]
    fn round_trips_empty_plaintext() {
        let (ct, nonce, tag) = encrypt(&KEY, b"", b"aad").unwrap();
        assert!(ct.is_empty());
        assert_eq!(decrypt(&KEY, &ct, &nonce, &tag, b"aad").unwrap(), b"");
    }

    #[test]
    fn wrong_aad_fails() {
        let (ct, nonce, tag) = encrypt(&KEY, b"secret", b"aad").unwrap();
        assert_eq!(
            decrypt(&KEY, &ct, &nonce, &tag, b"other"),
            Err(CryptoError::AuthFailed)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let (ct, nonce, tag) = encrypt(&KEY, b"secret", b"aad").unwrap();
        assert_eq!(
            decrypt(&[0x3c; 32], &ct, &nonce, &tag, b"aad"),
            Err(CryptoError::AuthFailed)
        );
    }

    #[test]
    fn flipped_ciphertext_bit_fails() {
        let (mut ct, nonce, tag) = encrypt(&KEY, b"secret", b"aad").unwrap();
        ct[0] ^= 1;
        assert_eq!(
            decrypt(&KEY, &ct, &nonce, &tag, b"aad"),
            Err(CryptoError::AuthFailed)
        );
    }

    /// The finding that motivated the length checks: a truncated tag must be rejected
    /// outright, not compared over its leading bytes.
    #[test]
    fn truncated_tag_is_rejected_at_every_length() {
        let (ct, nonce, tag) = encrypt(&KEY, b"secret", b"aad").unwrap();

        for len in [0usize, 1, 2, 4, 8, 12, 15, 17, 32] {
            let mut short = tag.to_vec();
            short.resize(len, 0);
            assert_eq!(
                decrypt(&KEY, &ct, &nonce, &short, b"aad"),
                Err(CryptoError::InvalidTagSize),
                "tag length {len} was not rejected"
            );
        }
    }

    #[test]
    fn wrong_nonce_length_is_rejected() {
        let (ct, _nonce, tag) = encrypt(&KEY, b"secret", b"aad").unwrap();

        for len in [0usize, 1, 8, 11, 13, 16] {
            let short = vec![0u8; len];
            assert_eq!(
                decrypt(&KEY, &ct, &short, &tag, b"aad"),
                Err(CryptoError::InvalidNonceSize),
                "nonce length {len} was not rejected"
            );
        }
    }

    #[test]
    fn wrong_key_size_is_a_distinct_error() {
        assert_eq!(
            encrypt(&[0u8; 16], b"x", b""),
            Err(CryptoError::InvalidKeySize)
        );
        assert_eq!(
            decrypt(&[0u8; 16], b"x", &[0u8; 12], &[0u8; 16], b""),
            Err(CryptoError::InvalidKeySize)
        );
    }

    #[test]
    fn nonces_are_fresh_per_encryption() {
        let (_, a, _) = encrypt(&KEY, b"x", b"").unwrap();
        let (_, b, _) = encrypt(&KEY, b"x", b"").unwrap();
        assert_ne!(a, b);
    }

    /// A known-answer test against NIST SP 800-38D / RFC 8452-style vectors, pinning the
    /// wire format independently of any other implementation in this repo.
    #[test]
    fn matches_a_known_answer_vector() {
        // NIST CAVP gcmEncryptExtIV256, Count 0: K = 0^256, IV = 0^96, P = "", A = ""
        let key = [0u8; 32];
        let (ct, _, tag) = encrypt_with_nonce(&key, b"", b"", [0u8; 12]).unwrap();
        assert!(ct.is_empty());
        assert_eq!(
            tag.to_vec(),
            hex(b"530f8afbc74536b9a963b4f1c4cb738b"),
            "GCM tag for the all-zero key/IV/empty message vector"
        );
    }

    fn hex(input: &[u8]) -> Vec<u8> {
        input
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
