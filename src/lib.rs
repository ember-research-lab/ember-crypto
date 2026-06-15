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

#[cfg(feature = "aead")]
pub mod aead;
#[cfg(feature = "aead")]
pub use aead::{AeadScheme, XChaCha20Poly1305Scheme};

/// Canonical algorithm ids — the crypto-agility header values. Stored on every key and signature and
/// matched by the [`SchemeRegistry`]. Never branch on anything else.
pub mod alg {
    /// Classical Ed25519 / EdDSA.
    pub const ED25519: &str = "ed25519";
    /// ML-DSA-65 (NIST FIPS-204), post-quantum.
    pub const ML_DSA_65: &str = "ml-dsa-65";
    /// Ed25519 + ML-DSA-65 robust combiner (both required to verify).
    pub const HYBRID_ED25519_ML_DSA_65: &str = "hybrid-ed25519-ml-dsa-65";
    /// XChaCha20-Poly1305 AEAD (symmetric authenticated encryption).
    pub const XCHACHA20_POLY1305: &str = "xchacha20-poly1305";
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
    /// An AEAD operation failed internally (RNG, or the cipher backend rejected the inputs). A
    /// failed *open* (bad tag / tamper / wrong key / wrong AAD) is [`VerificationFailed`], not this.
    Aead(&'static str),
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
            CryptoError::Aead(e) => write!(f, "aead operation failed: {e}"),
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

/// Fill a buffer with cryptographically secure random bytes from the OS CSPRNG. The org's single
/// CSPRNG entry point — token/session-id/nonce material everywhere draws from here, so a weak source
/// can never sneak into one consumer.
pub fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

/// `n` cryptographically secure random bytes from the OS CSPRNG, in a buffer that **zeroizes on
/// drop** (so token material doesn't linger in freed memory). The basis for [`random_hex`].
pub fn random_bytes(n: usize) -> zeroize::Zeroizing<Vec<u8>> {
    let mut v = zeroize::Zeroizing::new(vec![0u8; n]);
    fill_random(&mut v);
    v
}

/// A lowercase-hex token of `n_bytes` of CSPRNG entropy (the string is `2 * n_bytes` chars). The
/// standard way to mint an opaque, unguessable id (session id, login token, CSRF state). 16 bytes =
/// 128 bits is the common choice.
pub fn random_hex(n_bytes: usize) -> String {
    let raw = random_bytes(n_bytes);
    let mut s = String::with_capacity(n_bytes * 2);
    for b in raw.iter() {
        s.push(nibble_lower(b >> 4));
        s.push(nibble_lower(b & 0x0f));
    }
    s
}

/// HMAC-SHA1 of `msg` under `key` (20 bytes). The one MAC RFC-6238 **TOTP** needs (SHA-1 is the
/// default authenticator-app variant — Google Authenticator/Authy/1Password/etc.). HMAC's security
/// does **not** rest on SHA-1's broken collision resistance, so HMAC-SHA1 remains sound for TOTP;
/// don't reach for it for anything else. Gated behind `hmac-sha1` so the SHA-1 dep is opt-in.
#[cfg(feature = "hmac-sha1")]
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    use hmac::{Mac, SimpleHmac};
    let mut mac =
        SimpleHmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC takes a key of any size");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA256 of `msg` under `key` (32 bytes). The MAC behind modern **webhook request signing** —
/// Slack's `v0=` header, Stripe/GitHub `sha256=`. A receiver recomputes it over the raw request body
/// and [`ct_eq`]-compares against the sender's header to prove the request really came from the
/// platform (and wasn't tampered with). Gated behind `hmac-sha256`. SHA-256, unlike SHA-1, is also
/// collision-resistant, so this one is fine for general-purpose authentication.
#[cfg(feature = "hmac-sha256")]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::{Mac, SimpleHmac};
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any size");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// **Constant-time** byte-slice equality — no early-out on the first differing byte, so a secret
/// (a token hash, a MAC) isn't probeable through response timing. Unequal lengths return `false`
/// fast (the length is not itself the secret). The org's one constant-time compare.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn nibble_lower(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
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

    #[test]
    fn random_hex_is_unique_right_length_and_hex() {
        let a = random_hex(16);
        let b = random_hex(16);
        assert_eq!(a.len(), 32, "16 bytes → 32 hex chars");
        assert_ne!(a, b, "two draws differ (CSPRNG, not a constant)");
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(48).len(), 48);
    }

    #[cfg(feature = "hmac-sha1")]
    #[test]
    fn hmac_sha1_matches_rfc2202_vector() {
        // RFC 2202 test case 1: key = 0x0b × 20, data = "Hi There".
        let mac = hmac_sha1(&[0x0b; 20], b"Hi There");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[cfg(feature = "hmac-sha256")]
    #[test]
    fn hmac_sha256_matches_rfc4231_vector() {
        // RFC 4231 test case 1: key = 0x0b × 20, data = "Hi There".
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn ct_eq_matches_only_equal_slices() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"), "length differs");
        assert!(ct_eq(b"", b""));
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
