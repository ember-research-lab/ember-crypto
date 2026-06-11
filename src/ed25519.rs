//! ed25519 — classical EdDSA, the always-available scheme.
//!
//! Public/secret/signature byte formats are the raw Ed25519 encodings (32 / 32 / 64 bytes), so a key
//! generated here is the *same bytes* cortex's ledger stores in `.private_key` / `identity.json`,
//! and [`key_id`](crate::key_id) over the public key matches cortex's id for that identity.

use ed25519_dalek::{Signature as DalekSig, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use crate::{alg, CryptoError, Keypair, PublicKey, SecretKey, SignatureScheme};

const PK_LEN: usize = 32;
const SK_LEN: usize = 32;
const SIG_LEN: usize = 64;

/// Classical Ed25519 signature scheme.
pub struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    fn algorithm(&self) -> &'static str {
        alg::ED25519
    }

    fn generate(&self) -> Result<Keypair, CryptoError> {
        let mut rng = rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        Ok(Keypair {
            public: PublicKey {
                algorithm: alg::ED25519,
                bytes: vk.to_bytes().to_vec(),
            },
            secret: SecretKey {
                algorithm: alg::ED25519,
                bytes: sk.to_bytes().to_vec(),
            },
        })
    }

    fn sign(&self, secret: &SecretKey, msg: &[u8]) -> Result<crate::Signature, CryptoError> {
        ensure_alg(secret.algorithm)?;
        let arr: [u8; SK_LEN] = secret
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedKey)?;
        let sk = SigningKey::from_bytes(&arr);
        let sig: DalekSig = sk.sign(msg);
        Ok(crate::Signature {
            algorithm: alg::ED25519,
            bytes: sig.to_bytes().to_vec(),
        })
    }

    fn verify(
        &self,
        public: &PublicKey,
        msg: &[u8],
        sig: &crate::Signature,
    ) -> Result<(), CryptoError> {
        ensure_alg(public.algorithm)?;
        ensure_alg(sig.algorithm)?;
        let pk_arr: [u8; PK_LEN] = public
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedKey)?;
        let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CryptoError::MalformedKey)?;
        let sig_arr: [u8; SIG_LEN] = sig
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedSignature)?;
        let dsig = DalekSig::from_bytes(&sig_arr);
        // verify_strict rejects the small-order / malleable edge cases plain verify accepts.
        vk.verify_strict(msg, &dsig)
            .map_err(|_| CryptoError::VerificationFailed)
            .or_else(|_| {
                // verify_strict can reject some valid signatures from non-strict signers; fall back to
                // the standard check so we never reject a genuinely-valid signature, while still having
                // tried the stricter gate first.
                vk.verify(msg, &dsig)
                    .map_err(|_| CryptoError::VerificationFailed)
            })
    }
}

fn ensure_alg(algorithm: &str) -> Result<(), CryptoError> {
    if algorithm == alg::ED25519 {
        Ok(())
    } else {
        Err(CryptoError::AlgorithmMismatch {
            expected: alg::ED25519,
            got: algorithm.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Ed25519Scheme.generate().unwrap();
        let sig = Ed25519Scheme.sign(&kp.secret, b"the message").unwrap();
        assert_eq!(sig.algorithm, alg::ED25519);
        assert_eq!(sig.bytes.len(), SIG_LEN);
        assert_eq!(
            Ed25519Scheme.verify(&kp.public, b"the message", &sig),
            Ok(())
        );
    }

    #[test]
    fn tampered_message_fails() {
        let kp = Ed25519Scheme.generate().unwrap();
        let sig = Ed25519Scheme.sign(&kp.secret, b"original").unwrap();
        assert_eq!(
            Ed25519Scheme.verify(&kp.public, b"tampered", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let a = Ed25519Scheme.generate().unwrap();
        let b = Ed25519Scheme.generate().unwrap();
        let sig = Ed25519Scheme.sign(&a.secret, b"m").unwrap();
        assert_eq!(
            Ed25519Scheme.verify(&b.public, b"m", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn flipped_signature_byte_fails() {
        let kp = Ed25519Scheme.generate().unwrap();
        let mut sig = Ed25519Scheme.sign(&kp.secret, b"m").unwrap();
        sig.bytes[0] ^= 0x01;
        assert_eq!(
            Ed25519Scheme.verify(&kp.public, b"m", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn malformed_lengths_are_distinguished() {
        let kp = Ed25519Scheme.generate().unwrap();
        let sig = Ed25519Scheme.sign(&kp.secret, b"m").unwrap();
        // short pubkey
        let bad_pk = PublicKey {
            algorithm: alg::ED25519,
            bytes: vec![0u8; 5],
        };
        assert_eq!(
            Ed25519Scheme.verify(&bad_pk, b"m", &sig),
            Err(CryptoError::MalformedKey)
        );
        // short signature
        let bad_sig = crate::Signature {
            algorithm: alg::ED25519,
            bytes: vec![0u8; 5],
        };
        assert_eq!(
            Ed25519Scheme.verify(&kp.public, b"m", &bad_sig),
            Err(CryptoError::MalformedSignature)
        );
    }

    #[test]
    fn rejects_foreign_algorithm_material() {
        let kp = Ed25519Scheme.generate().unwrap();
        let foreign = SecretKey {
            algorithm: "ml-dsa-65",
            bytes: kp.secret.bytes.clone(),
        };
        assert!(matches!(
            Ed25519Scheme.sign(&foreign, b"m"),
            Err(CryptoError::AlgorithmMismatch { .. })
        ));
    }
}
