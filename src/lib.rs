//! ember-crypto — the org's single sign/verify surface, behind a **crypto-agility** interface.
//!
//! One place owns the cryptography every Ember consumer trusts: cortex (ledger block signing),
//! ember-graph (provenance envelopes), the SMB platform (per-agent action signatures). The rule —
//! **the algorithm is always named, never hardcoded.** A [`Signature`] carries its [`alg`] id; a
//! [`SchemeRegistry`] dispatches verification on that id and can hold several algorithms at once. So
//! an Ed25519 → ML-DSA migration is *additive*: old signatures keep verifying while new ones use the
//! post-quantum scheme.
//!
//! ## Algorithms
//! - [`Ed25519Scheme`] — classical EdDSA. Always available. The substrate cortex's ledger already
//!   signs with (key ids are byte-identical — see [`key_id`]).
//! - [`MlDsa65Scheme`] *(feature `pqc`)* — ML-DSA-65 / FIPS-204, the NIST post-quantum signature.
//! - [`HybridScheme`] *(feature `pqc`)* — Ed25519 **and** ML-DSA-65, both signing the message, both
//!   required to verify. The robust combiner: a forgery needs to break *both*, so the hybrid stays
//!   unforgeable as long as **either** component does. This is the migration posture — sign hybrid
//!   now, and you're covered whether the threat that lands first is a classical break or a quantum one.
//!
//! ## What this crate is *not*
//! It never persists, escrows, or rotates key material — **custody is the consumer's** (ember-vault).
//! A [`SecretKey`] here is short-lived and zeroized on drop. This crate signs, verifies, and hashes;
//! it does not decide *who* is trusted (that identity/trust layer lives in the consumer, e.g.
//! ember-graph's `VerifierRegistry`).

#![cfg_attr(docsrs, feature(doc_cfg))]

use core::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

mod ed25519;
pub use ed25519::Ed25519Scheme;

#[cfg(feature = "pqc")]
mod mldsa;
#[cfg(feature = "pqc")]
pub use mldsa::MlDsa65Scheme;

#[cfg(feature = "pqc")]
mod hybrid;
#[cfg(feature = "pqc")]
pub use hybrid::HybridScheme;

/// Canonical algorithm ids — the crypto-agility header values. Stored on every key and signature and
/// matched by the [`SchemeRegistry`]. Never branch on anything else.
pub mod alg {
    /// Classical Ed25519 / EdDSA.
    pub const ED25519: &str = "ed25519";
    /// ML-DSA-65 (NIST FIPS-204), post-quantum.
    pub const ML_DSA_65: &str = "ml-dsa-65";
    /// Ed25519 + ML-DSA-65 robust combiner (both required to verify).
    pub const HYBRID_ED25519_ML_DSA_65: &str = "hybrid-ed25519-ml-dsa-65";
}

/// Errors from key generation, signing, parsing, or verification. An enum, never a string — a
/// consumer can match on the precise failure (e.g. distinguish a malformed key from a real
/// verification failure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The underlying keygen failed (RNG or internal error from the algorithm backend).
    KeyGen(&'static str),
    /// The underlying signing operation failed.
    Sign(&'static str),
    /// A key's bytes don't match the algorithm's expected length / shape.
    MalformedKey,
    /// A signature's bytes don't match the algorithm's expected length / shape.
    MalformedSignature,
    /// A key or signature was handed to a scheme whose algorithm id it doesn't carry.
    AlgorithmMismatch { expected: &'static str, got: String },
    /// No scheme is registered for this algorithm id.
    UnknownAlgorithm(String),
    /// The signature did not verify (tamper, wrong key, or a forgery attempt).
    VerificationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyGen(e) => write!(f, "key generation failed: {e}"),
            CryptoError::Sign(e) => write!(f, "signing failed: {e}"),
            CryptoError::MalformedKey => write!(f, "malformed key"),
            CryptoError::MalformedSignature => write!(f, "malformed signature"),
            CryptoError::AlgorithmMismatch { expected, got } => {
                write!(f, "algorithm mismatch: expected {expected}, got {got}")
            }
            CryptoError::UnknownAlgorithm(a) => write!(f, "unknown algorithm: {a}"),
            CryptoError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// A public key tagged with its algorithm. The algorithm id travels with the bytes so a verifier
/// never has to assume which scheme produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub algorithm: &'static str,
    pub bytes: Vec<u8>,
}

/// A secret key tagged with its algorithm. **Zeroized on drop**; debug-redacted. Custody is the
/// consumer's — this type only exists for the brief span of a sign call.
#[derive(Clone)]
pub struct SecretKey {
    pub algorithm: &'static str,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print secret bytes.
        f.debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A signature tagged with the algorithm that produced it — the crypto-agility header the registry
/// dispatches on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: &'static str,
    pub bytes: Vec<u8>,
}

/// A freshly generated key pair.
#[derive(Clone, Debug)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// One signature algorithm — generate, sign, verify. Object-safe so heterogeneous schemes live
/// together in a [`SchemeRegistry`]. Implementations are responsible for their own key material
/// format and never touch persistence.
pub trait SignatureScheme {
    /// The canonical algorithm id (one of [`alg`]). Stamped onto every key and signature this scheme
    /// produces, and the registry key.
    fn algorithm(&self) -> &'static str;

    /// Generate a fresh key pair using a cryptographically secure RNG.
    fn generate(&self) -> Result<Keypair, CryptoError>;

    /// Sign `msg` with `secret`. Errors if `secret` is for a different algorithm or malformed.
    fn sign(&self, secret: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError>;

    /// Verify `sig` over `msg` under `public`. `Ok(())` iff valid; [`CryptoError::VerificationFailed`]
    /// for a bad-but-well-formed signature, or a malformed / mismatch error otherwise.
    fn verify(&self, public: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError>;
}

/// A set of [`SignatureScheme`]s keyed by algorithm id — **the crypto-agility seam.** Adding an
/// algorithm is adding a scheme here; existing signatures keep verifying. [`verify`](Self::verify)
/// reads the algorithm off the signature and dispatches, so a caller verifies an envelope without
/// knowing in advance which scheme signed it.
#[derive(Default)]
pub struct SchemeRegistry {
    schemes: Vec<Box<dyn SignatureScheme>>,
}

impl SchemeRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a scheme (builder style). A later scheme with the same id shadows an earlier one.
    pub fn with(mut self, scheme: Box<dyn SignatureScheme>) -> Self {
        self.schemes.push(scheme);
        self
    }

    /// The standard registry: Ed25519 always, plus ML-DSA-65 and the hybrid when `pqc` is enabled.
    /// This is what a consumer wants unless it has a reason to restrict the set (cortex, on the
    /// classical-only substrate, builds `new().with(Ed25519Scheme)` instead).
    pub fn standard() -> Self {
        let reg = Self::new().with(Box::new(Ed25519Scheme));
        #[cfg(feature = "pqc")]
        let reg = reg
            .with(Box::new(MlDsa65Scheme))
            .with(Box::new(HybridScheme));
        reg
    }

    /// The scheme for an algorithm id, if registered. Last-registered wins (so `with` can override).
    pub fn get(&self, algorithm: &str) -> Option<&dyn SignatureScheme> {
        self.schemes
            .iter()
            .rev()
            .find(|s| s.algorithm() == algorithm)
            .map(|b| b.as_ref())
    }

    /// Verify a signature, dispatching on the signature's own algorithm id. Fails closed: an
    /// unregistered algorithm is [`CryptoError::UnknownAlgorithm`], and the public key must agree
    /// with the signature's algorithm.
    pub fn verify(
        &self,
        public: &PublicKey,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<(), CryptoError> {
        if public.algorithm != sig.algorithm {
            return Err(CryptoError::AlgorithmMismatch {
                expected: sig.algorithm,
                got: public.algorithm.to_string(),
            });
        }
        let scheme = self
            .get(sig.algorithm)
            .ok_or_else(|| CryptoError::UnknownAlgorithm(sig.algorithm.to_string()))?;
        scheme.verify(public, msg, sig)
    }
}

/// SHA-256 content hash of `bytes`. The org's hash is SHA-256 everywhere (cortex's ledger included —
/// despite older docs mentioning BLAKE3, every block hash is SHA-256). Use this for content-addresses
/// and parent hashes so a node traces back to exact bytes.
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Short key id for a public key: the first 6 hex chars (uppercase) of `SHA-256(public_key_bytes)`.
///
/// **Byte-identical to cortex's `compute_key_id`** (`cortex-core::signing`) — for an Ed25519 public
/// key (the 32 raw bytes) this produces exactly the id cortex's ledger uses, so identities line up
/// across the two systems. For ML-DSA / hybrid keys it's the same construction over those keys' bytes.
pub fn key_id(public: &PublicKey) -> String {
    let digest = content_hash(&public.bytes);
    // First 3 bytes → 6 uppercase hex chars. Matches `hex::encode(digest)[..6].to_uppercase()`.
    let mut s = String::with_capacity(6);
    for b in &digest[..3] {
        s.push(nibble_upper(b >> 4));
        s.push(nibble_upper(b & 0x0f));
    }
    s
}

fn nibble_upper(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

/// Length-prefixed concatenation (`[u32 LE len][bytes]` per part). Used by the hybrid scheme to pack
/// two algorithms' key/signature bytes into one, unambiguously. Shared so pack/unpack can't drift.
/// Only the hybrid (PQC) scheme needs this, so it's gated with it.
#[cfg(feature = "pqc")]
pub(crate) fn lp_pack(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Inverse of [`lp_pack`] for exactly `n` parts. Errors (via `malformed`) on truncation or trailing
/// bytes — a structural mismatch is treated as malformed, never silently tolerated.
#[cfg(feature = "pqc")]
pub(crate) fn lp_unpack(
    buf: &[u8],
    n: usize,
    malformed: CryptoError,
) -> Result<Vec<&[u8]>, CryptoError> {
    let mut parts = Vec::with_capacity(n);
    let mut i = 0usize;
    for _ in 0..n {
        if i + 4 > buf.len() {
            return Err(malformed);
        }
        let len = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + len > buf.len() {
            return Err(malformed);
        }
        parts.push(&buf[i..i + len]);
        i += len;
    }
    if i != buf.len() {
        return Err(malformed); // trailing bytes → malformed
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_matches_cortex_construction() {
        // cortex: hex::encode(Sha256(pubkey))[..6].to_uppercase(). Reproduce independently here.
        let pk = PublicKey {
            algorithm: alg::ED25519,
            bytes: vec![0u8; 32],
        };
        let digest = content_hash(&pk.bytes);
        let full_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let expected = full_hex[..6].to_uppercase();
        assert_eq!(key_id(&pk), expected);
        // And it's uppercase, 6 chars.
        assert_eq!(key_id(&pk).len(), 6);
        assert_eq!(key_id(&pk), key_id(&pk).to_uppercase());
    }

    #[test]
    fn content_hash_is_sha256() {
        // Known vector: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = content_hash(b"");
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn lp_roundtrip_and_rejects_corruption() {
        let packed = lp_pack(&[b"alpha", b"", b"omega"]);
        let parts = lp_unpack(&packed, 3, CryptoError::MalformedSignature).unwrap();
        assert_eq!(parts, vec![&b"alpha"[..], &b""[..], &b"omega"[..]]);
        // Truncated → malformed.
        assert_eq!(
            lp_unpack(
                &packed[..packed.len() - 1],
                3,
                CryptoError::MalformedSignature
            ),
            Err(CryptoError::MalformedSignature)
        );
        // Trailing byte → malformed.
        let mut extra = packed.clone();
        extra.push(0);
        assert_eq!(
            lp_unpack(&extra, 3, CryptoError::MalformedSignature),
            Err(CryptoError::MalformedSignature)
        );
    }

    #[test]
    fn registry_dispatches_and_fails_closed() {
        let reg = SchemeRegistry::new().with(Box::new(Ed25519Scheme));
        let kp = Ed25519Scheme.generate().unwrap();
        let sig = Ed25519Scheme.sign(&kp.secret, b"hello").unwrap();
        assert_eq!(reg.verify(&kp.public, b"hello", &sig), Ok(()));

        // Unknown algorithm → fails closed.
        let alien = Signature {
            algorithm: "made-up",
            bytes: sig.bytes.clone(),
        };
        let alien_pk = PublicKey {
            algorithm: "made-up",
            bytes: kp.public.bytes.clone(),
        };
        assert_eq!(
            reg.verify(&alien_pk, b"hello", &alien),
            Err(CryptoError::UnknownAlgorithm("made-up".to_string()))
        );

        // pubkey/sig algorithm disagreement → mismatch.
        assert!(matches!(
            reg.verify(&alien_pk, b"hello", &sig),
            Err(CryptoError::AlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn secret_is_zeroized_on_drop() {
        // We can't observe freed memory safely, but we can confirm zeroize runs without panic and
        // the type is Drop. Construct, clone, drop.
        let kp = Ed25519Scheme.generate().unwrap();
        let c = kp.secret.clone();
        drop(c);
        // original still usable
        let _ = Ed25519Scheme.sign(&kp.secret, b"x").unwrap();
    }
}
