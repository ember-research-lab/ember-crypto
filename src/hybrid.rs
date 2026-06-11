//! hybrid — Ed25519 **and** ML-DSA-65, the migration posture.
//!
//! Both components sign the same message; **both must verify**. This is the robust signature combiner:
//! an existential forgery on the hybrid requires forging *both* components, so the hybrid is
//! unforgeable as long as **either** Ed25519 or ML-DSA-65 is. You get classical security today and
//! post-quantum security against "harvest now, forge later" — without betting on which break lands
//! first, and without throwing away Ed25519's decades of scrutiny.
//!
//! Key and signature bytes are the two components packed length-prefixed (`ed25519 || ml-dsa-65`) via
//! [`lp_pack`](crate::lp_pack) — unambiguous, and the same packer/unpacker so they can't drift.

use crate::{
    alg, ed25519::Ed25519Scheme, lp_pack, lp_unpack, mldsa::MlDsa65Scheme, CryptoError, Keypair,
    PublicKey, SecretKey, Signature, SignatureScheme,
};

/// Ed25519 + ML-DSA-65 robust combiner. Both sign; both must verify.
pub struct HybridScheme;

impl SignatureScheme for HybridScheme {
    fn algorithm(&self) -> &'static str {
        alg::HYBRID_ED25519_ML_DSA_65
    }

    fn generate(&self) -> Result<Keypair, CryptoError> {
        let ed = Ed25519Scheme.generate()?;
        let pq = MlDsa65Scheme.generate()?;
        Ok(Keypair {
            public: PublicKey {
                algorithm: alg::HYBRID_ED25519_ML_DSA_65,
                bytes: lp_pack(&[&ed.public.bytes, &pq.public.bytes]),
            },
            secret: SecretKey {
                algorithm: alg::HYBRID_ED25519_ML_DSA_65,
                bytes: lp_pack(&[&ed.secret.bytes, &pq.secret.bytes]),
            },
        })
    }

    fn sign(&self, secret: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
        ensure_alg(secret.algorithm)?;
        let parts = lp_unpack(&secret.bytes, 2, CryptoError::MalformedKey)?;
        let ed_sk = SecretKey {
            algorithm: alg::ED25519,
            bytes: parts[0].to_vec(),
        };
        let pq_sk = SecretKey {
            algorithm: alg::ML_DSA_65,
            bytes: parts[1].to_vec(),
        };
        let ed_sig = Ed25519Scheme.sign(&ed_sk, msg)?;
        let pq_sig = MlDsa65Scheme.sign(&pq_sk, msg)?;
        Ok(Signature {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65,
            bytes: lp_pack(&[&ed_sig.bytes, &pq_sig.bytes]),
        })
    }

    fn verify(&self, public: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        ensure_alg(public.algorithm)?;
        ensure_alg(sig.algorithm)?;
        let pk_parts = lp_unpack(&public.bytes, 2, CryptoError::MalformedKey)?;
        let sig_parts = lp_unpack(&sig.bytes, 2, CryptoError::MalformedSignature)?;

        let ed_pk = PublicKey {
            algorithm: alg::ED25519,
            bytes: pk_parts[0].to_vec(),
        };
        let ed_sig = Signature {
            algorithm: alg::ED25519,
            bytes: sig_parts[0].to_vec(),
        };
        let pq_pk = PublicKey {
            algorithm: alg::ML_DSA_65,
            bytes: pk_parts[1].to_vec(),
        };
        let pq_sig = Signature {
            algorithm: alg::ML_DSA_65,
            bytes: sig_parts[1].to_vec(),
        };

        // BOTH must verify. A malformed component surfaces as its own error; a well-formed-but-bad
        // component is VerificationFailed. Either way, no partial acceptance.
        Ed25519Scheme.verify(&ed_pk, msg, &ed_sig)?;
        MlDsa65Scheme.verify(&pq_pk, msg, &pq_sig)?;
        Ok(())
    }
}

fn ensure_alg(algorithm: &str) -> Result<(), CryptoError> {
    if algorithm == alg::HYBRID_ED25519_ML_DSA_65 {
        Ok(())
    } else {
        Err(CryptoError::AlgorithmMismatch {
            expected: alg::HYBRID_ED25519_ML_DSA_65,
            got: algorithm.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = HybridScheme.generate().unwrap();
        assert_eq!(kp.public.algorithm, alg::HYBRID_ED25519_ML_DSA_65);
        let sig = HybridScheme.sign(&kp.secret, b"both must hold").unwrap();
        assert_eq!(
            HybridScheme.verify(&kp.public, b"both must hold", &sig),
            Ok(())
        );
    }

    #[test]
    fn tampered_message_fails() {
        let kp = HybridScheme.generate().unwrap();
        let sig = HybridScheme.sign(&kp.secret, b"original").unwrap();
        assert_eq!(
            HybridScheme.verify(&kp.public, b"tampered", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn breaking_only_the_ed25519_half_still_fails() {
        // Forge the Ed25519 component (flip its first byte); the ML-DSA half is untouched and valid.
        // Robust combiner ⇒ overall verification still fails, because BOTH are required.
        let kp = HybridScheme.generate().unwrap();
        let sig = HybridScheme.sign(&kp.secret, b"m").unwrap();
        let mut parts: Vec<Vec<u8>> = lp_unpack(&sig.bytes, 2, CryptoError::MalformedSignature)
            .unwrap()
            .into_iter()
            .map(|p| p.to_vec())
            .collect();
        parts[0][0] ^= 0x01; // corrupt the ed25519 signature only
        let forged = Signature {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65,
            bytes: lp_pack(&[&parts[0], &parts[1]]),
        };
        assert_eq!(
            HybridScheme.verify(&kp.public, b"m", &forged),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn breaking_only_the_mldsa_half_still_fails() {
        // Symmetric: corrupt the ML-DSA component only; the Ed25519 half is valid. Still fails.
        let kp = HybridScheme.generate().unwrap();
        let sig = HybridScheme.sign(&kp.secret, b"m").unwrap();
        let mut parts: Vec<Vec<u8>> = lp_unpack(&sig.bytes, 2, CryptoError::MalformedSignature)
            .unwrap()
            .into_iter()
            .map(|p| p.to_vec())
            .collect();
        parts[1][0] ^= 0x01; // corrupt the ml-dsa signature only
        let forged = Signature {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65,
            bytes: lp_pack(&[&parts[0], &parts[1]]),
        };
        assert_eq!(
            HybridScheme.verify(&kp.public, b"m", &forged),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let a = HybridScheme.generate().unwrap();
        let b = HybridScheme.generate().unwrap();
        let sig = HybridScheme.sign(&a.secret, b"m").unwrap();
        assert_eq!(
            HybridScheme.verify(&b.public, b"m", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn malformed_packing_is_distinguished() {
        let kp = HybridScheme.generate().unwrap();
        let sig = HybridScheme.sign(&kp.secret, b"m").unwrap();
        let bad_pk = PublicKey {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65,
            bytes: vec![0u8; 3], // too short to even hold a length prefix
        };
        assert_eq!(
            HybridScheme.verify(&bad_pk, b"m", &sig),
            Err(CryptoError::MalformedKey)
        );
    }
}
