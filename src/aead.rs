//! aead — authenticated encryption (XChaCha20-Poly1305) behind the crypto-agility seam.
//!
//! The org's symmetric AEAD primitive: **seal/open** under a caller-held key, with associated data
//! (AAD) bound into the authentication tag. Used for at-rest encryption of per-subject PII (the SMB
//! platform's *crypto-shred* erasure — destroy the per-subject key and the ciphertext is
//! unrecoverable) and as the cipher behind ember-vault's sealed-at-rest backend. Like the signature
//! schemes, the algorithm is **named** (`alg::XCHACHA20_POLY1305`), never hardcoded at the call
//! site — additive crypto-agility.
//!
//! **Why XChaCha20-Poly1305** (extended 192-bit nonce): a *random* per-message nonce is safe with no
//! practical reuse risk, so the caller never has to manage a nonce counter — the right default for
//! encrypting many records under one long-lived key. The 16-byte Poly1305 tag authenticates both the
//! ciphertext and the AAD.
//!
//! **Custody is the consumer's.** This crate generates and operates on key bytes but never persists
//! them — the DEK lives in ember-vault; destroying it there is what makes erasure cryptographic.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{alg, CryptoError};

/// XChaCha20-Poly1305 key length (256-bit).
const KEY_LEN: usize = 32;
/// XChaCha20 extended nonce length (192-bit).
const NONCE_LEN: usize = 24;
/// Poly1305 tag length appended by the cipher.
const TAG_LEN: usize = 16;

/// One AEAD algorithm — generate a key, seal, open. Object-safe so schemes compose like the
/// [`SignatureScheme`](crate::SignatureScheme)s. Implementations never persist key material.
pub trait AeadScheme {
    /// The canonical algorithm id (one of [`alg`]).
    fn algorithm(&self) -> &'static str;
    /// The key length in bytes this scheme expects.
    fn key_len(&self) -> usize;
    /// A fresh random key (a data-encryption key / DEK) from a cryptographically secure RNG, wrapped
    /// in [`Zeroizing`] so it's wiped from memory when the caller drops it (consistent with this
    /// crate's `SecretKey` hygiene). The caller persists the bytes in its vault; this crate never
    /// stores them.
    fn generate_key(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    /// Seal `plaintext` under `key`, binding `aad` into the tag. Output = **nonce ‖ ciphertext ‖
    /// tag**; a fresh random nonce is generated per call (so the same plaintext seals differently
    /// each time). `Err(MalformedKey)` if `key` is the wrong length.
    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Open a blob produced by [`seal`](AeadScheme::seal) with the **same key and AAD**.
    /// `Err(VerificationFailed)` on a bad tag — tamper, wrong key, or wrong AAD (the bytes are
    /// never returned in that case); `Err(MalformedKey)` / `MalformedSignature` for wrong-length
    /// inputs.
    fn open(&self, key: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// XChaCha20-Poly1305 AEAD scheme.
pub struct XChaCha20Poly1305Scheme;

impl AeadScheme for XChaCha20Poly1305Scheme {
    fn algorithm(&self) -> &'static str {
        alg::XCHACHA20_POLY1305
    }

    fn key_len(&self) -> usize {
        KEY_LEN
    }

    fn generate_key(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut key)
            .map_err(|_| CryptoError::Aead("rng"))?;
        Ok(key)
    }

    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = key_of(key)?;
        let cipher = XChaCha20Poly1305::new(key);
        // A fresh random 192-bit nonce per message — reuse-safe without a counter.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| CryptoError::Aead("rng"))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Aead("seal"))?;
        // nonce ‖ ciphertext+tag
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, key: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = key_of(key)?;
        // Must at least hold a nonce + an (empty-plaintext) tag.
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::MalformedSignature);
        }
        let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
        let cipher = XChaCha20Poly1305::new(key);
        cipher
            .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad })
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

/// Validate the key length and view it as the cipher's `Key` (no copy of secret bytes beyond the
/// borrow). Wrong length is a malformed key, distinct from a verification failure.
fn key_of(key: &[u8]) -> Result<&Key, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::MalformedKey);
    }
    Ok(Key::from_slice(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_with_aad() {
        let s = XChaCha20Poly1305Scheme;
        let key = s.generate_key().unwrap();
        assert_eq!(key.len(), KEY_LEN);
        let aad = b"tenant=acme|contact:c1|name";
        let pt = b"Jane Doe";
        let sealed = s.seal(&key, aad, pt).unwrap();
        // ciphertext is not the plaintext, and carries nonce + tag overhead.
        assert!(!sealed.windows(pt.len()).any(|w| w == pt));
        assert_eq!(sealed.len(), NONCE_LEN + pt.len() + TAG_LEN);
        assert_eq!(s.open(&key, aad, &sealed).unwrap(), pt);
    }

    #[test]
    fn nonce_is_random_each_seal() {
        let s = XChaCha20Poly1305Scheme;
        let key = s.generate_key().unwrap();
        let a = s.seal(&key, b"", b"same").unwrap();
        let b = s.seal(&key, b"", b"same").unwrap();
        assert_ne!(a, b, "fresh nonce ⇒ same plaintext seals differently");
        assert_eq!(s.open(&key, b"", &a).unwrap(), b"same");
        assert_eq!(s.open(&key, b"", &b).unwrap(), b"same");
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let s = XChaCha20Poly1305Scheme;
        let k1 = s.generate_key().unwrap();
        let k2 = s.generate_key().unwrap();
        let sealed = s.seal(&k1, b"", b"secret").unwrap();
        assert_eq!(
            s.open(&k2, b"", &sealed),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_aad_fails_to_open() {
        // AAD is authenticated — opening with different associated data must fail (this is what
        // binds a ciphertext to its tenant/record/field so it can't be moved).
        let s = XChaCha20Poly1305Scheme;
        let key = s.generate_key().unwrap();
        let sealed = s.seal(&key, b"contact:c1", b"x").unwrap();
        assert_eq!(
            s.open(&key, b"contact:c2", &sealed),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let s = XChaCha20Poly1305Scheme;
        let key = s.generate_key().unwrap();
        let mut sealed = s.seal(&key, b"", b"important").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // flip a tag byte
        assert_eq!(
            s.open(&key, b"", &sealed),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn malformed_key_and_short_input_are_distinguished() {
        let s = XChaCha20Poly1305Scheme;
        assert_eq!(s.seal(&[0u8; 8], b"", b"x"), Err(CryptoError::MalformedKey));
        let key = s.generate_key().unwrap();
        assert_eq!(
            s.open(&key, b"", &[0u8; 4]),
            Err(CryptoError::MalformedSignature)
        );
    }

    #[test]
    fn destroyed_key_makes_ciphertext_unrecoverable() {
        // The crypto-shred property: once the DEK is gone, the ciphertext can't be opened by anyone
        // (no key recovery from the blob) — only a fresh wrong key remains, which fails.
        let s = XChaCha20Poly1305Scheme;
        let key = s.generate_key().unwrap();
        let sealed = s.seal(&key, b"contact:c1", b"PII").unwrap();
        drop(key); // the vault destroyed it
        let any_other = s.generate_key().unwrap();
        assert_eq!(
            s.open(&any_other, b"contact:c1", &sealed),
            Err(CryptoError::VerificationFailed)
        );
    }

    /// **Frozen wire-format vector** (crypto-review #3). A blob this implementation sealed once, with
    /// a fixed key + AAD, must keep decrypting to the same plaintext forever — so a future dep bump,
    /// a re-implementation, or a framing change can't silently change the on-disk format and orphan
    /// stored ciphertext (at-rest data outlives the code that wrote it). The blob carries its own
    /// random nonce, so we pin `open(blob)`, not `seal()`.
    #[test]
    fn frozen_blob_still_decodes() {
        let blob = hex(
            "a12520009adb27318c8e545f9b8a93b76013a073d6227373ed9a88dc6611ad46\
             d68dbe55c461e631b64bd09196805e08",
        );
        let key = [7u8; KEY_LEN];
        let out = XChaCha20Poly1305Scheme
            .open(&key, b"tenant=acme|contact:c1|name", &blob)
            .expect("the frozen XChaCha20-Poly1305 blob must still open (wire format is stable)");
        assert_eq!(out, b"Jane Doe");
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
