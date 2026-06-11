//! mldsa — ML-DSA-65 (NIST FIPS-204), the post-quantum signature scheme.
//!
//! Backed by the pure-Rust `fips204` crate (no C, no aws-lc-rs) — the auditable choice that fits the
//! Ember suite's ethos. ML-DSA-65 is the middle parameter set (NIST security category 3): public key
//! 1952 B, secret key 4032 B, signature 3309 B.
//!
//! Signing uses the empty FIPS-204 context string (`ctx = b""`). Domain separation between *facts* is
//! the consumer's job — they bind the subject id into the message they hand us (ember-graph's
//! `signed_payload` already length-prefixes the subject), so we don't overload `ctx` for it.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _, Verifier as _};

use crate::{alg, CryptoError, Keypair, PublicKey, SecretKey, Signature, SignatureScheme};

/// Empty FIPS-204 signing context. Subject/domain binding happens in the message, not here.
const CTX: &[u8] = b"";

/// ML-DSA-65 / FIPS-204 post-quantum signature scheme.
pub struct MlDsa65Scheme;

impl SignatureScheme for MlDsa65Scheme {
    fn algorithm(&self) -> &'static str {
        alg::ML_DSA_65
    }

    fn generate(&self) -> Result<Keypair, CryptoError> {
        let (pk, sk) = ml_dsa_65::try_keygen().map_err(CryptoError::KeyGen)?;
        Ok(Keypair {
            public: PublicKey {
                algorithm: alg::ML_DSA_65,
                bytes: pk.into_bytes().to_vec(),
            },
            secret: SecretKey {
                algorithm: alg::ML_DSA_65,
                bytes: sk.into_bytes().to_vec(),
            },
        })
    }

    fn sign(&self, secret: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
        ensure_alg(secret.algorithm)?;
        let sk_arr: [u8; ml_dsa_65::SK_LEN] = secret
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedKey)?;
        let sk =
            ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|_| CryptoError::MalformedKey)?;
        let sig = sk.try_sign(msg, CTX).map_err(CryptoError::Sign)?;
        Ok(Signature {
            algorithm: alg::ML_DSA_65,
            bytes: sig.to_vec(),
        })
    }

    fn verify(&self, public: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        ensure_alg(public.algorithm)?;
        ensure_alg(sig.algorithm)?;
        let pk_arr: [u8; ml_dsa_65::PK_LEN] = public
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedKey)?;
        let pk =
            ml_dsa_65::PublicKey::try_from_bytes(pk_arr).map_err(|_| CryptoError::MalformedKey)?;
        let sig_arr: [u8; ml_dsa_65::SIG_LEN] = sig
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedSignature)?;
        if pk.verify(msg, &sig_arr, CTX) {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

fn ensure_alg(algorithm: &str) -> Result<(), CryptoError> {
    if algorithm == alg::ML_DSA_65 {
        Ok(())
    } else {
        Err(CryptoError::AlgorithmMismatch {
            expected: alg::ML_DSA_65,
            got: algorithm.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = MlDsa65Scheme.generate().unwrap();
        assert_eq!(kp.public.bytes.len(), ml_dsa_65::PK_LEN);
        assert_eq!(kp.secret.bytes.len(), ml_dsa_65::SK_LEN);
        let sig = MlDsa65Scheme
            .sign(&kp.secret, b"quantum-resistant")
            .unwrap();
        assert_eq!(sig.algorithm, alg::ML_DSA_65);
        assert_eq!(sig.bytes.len(), ml_dsa_65::SIG_LEN);
        assert_eq!(
            MlDsa65Scheme.verify(&kp.public, b"quantum-resistant", &sig),
            Ok(())
        );
    }

    #[test]
    fn tampered_message_fails() {
        let kp = MlDsa65Scheme.generate().unwrap();
        let sig = MlDsa65Scheme.sign(&kp.secret, b"original").unwrap();
        assert_eq!(
            MlDsa65Scheme.verify(&kp.public, b"tampered", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let a = MlDsa65Scheme.generate().unwrap();
        let b = MlDsa65Scheme.generate().unwrap();
        let sig = MlDsa65Scheme.sign(&a.secret, b"m").unwrap();
        assert_eq!(
            MlDsa65Scheme.verify(&b.public, b"m", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn flipped_signature_byte_fails() {
        let kp = MlDsa65Scheme.generate().unwrap();
        let mut sig = MlDsa65Scheme.sign(&kp.secret, b"m").unwrap();
        sig.bytes[0] ^= 0x01;
        assert_eq!(
            MlDsa65Scheme.verify(&kp.public, b"m", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn malformed_key_is_distinguished() {
        let kp = MlDsa65Scheme.generate().unwrap();
        let sig = MlDsa65Scheme.sign(&kp.secret, b"m").unwrap();
        let bad_pk = PublicKey {
            algorithm: alg::ML_DSA_65,
            bytes: vec![0u8; 10],
        };
        assert_eq!(
            MlDsa65Scheme.verify(&bad_pk, b"m", &sig),
            Err(CryptoError::MalformedKey)
        );
    }
}
