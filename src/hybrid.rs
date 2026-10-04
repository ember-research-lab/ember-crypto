//! hybrid — Ed25519 **and** ML-DSA-65, the migration posture.
//!
//! Both components sign the message; **both must verify**. This is the robust signature combiner:
//! an existential forgery on the hybrid requires forging *both* components, so the hybrid is
//! unforgeable as long as **either** Ed25519 or ML-DSA-65 is. You get classical security today and
//! post-quantum security against "harvest now, forge later" — without betting on which break lands
//! first, and without throwing away Ed25519's decades of scrutiny.
//!
//! Two versions, told apart by algorithm id:
//! - [`HybridV2Scheme`] (`hybrid-ed25519-ml-dsa-65-v2`) — **sign with this one.** Each component
//!   signs under a hybrid-only domain: Ed25519 signs [`V2_DOMAIN`] `|| 0x00 || msg`, and ML-DSA-65
//!   signs `msg` with FIPS-204 context [`V2_DOMAIN`]. A component lifted out of a v2 signature is
//!   therefore not a valid standalone Ed25519 or ML-DSA-65 signature on `msg`, so a verifier that
//!   trusts a bare component key cannot be handed a stripped-down hybrid.
//! - [`HybridScheme`] (`hybrid-ed25519-ml-dsa-65`, v1) — both components sign the raw `msg` with no
//!   domain, so each component of a v1 signature *is* a valid standalone signature. Kept so existing
//!   v1 signatures keep verifying; don't sign new data with it.
//!
//! Key and signature bytes are the two components packed length-prefixed (`ed25519 || ml-dsa-65`) via
//! [`lp_pack`](crate::lp_pack) — unambiguous, and the same packer/unpacker so they can't drift. The
//! layout is the same in both versions; only the algorithm id and the signed bytes differ, and the
//! algorithm id on every key and signature keeps them apart (relabelling a v1 signature as v2 fails
//! verification, because v2 checks the domain-separated bytes).

use crate::{
    alg, ed25519::Ed25519Scheme, lp_pack, lp_unpack, mldsa, mldsa::MlDsa65Scheme, CryptoError,
    Keypair, PublicKey, SecretKey, Signature, SignatureScheme,
};

/// The v2 hybrid domain: the Ed25519 prefix (followed by one `0x00`) and the ML-DSA-65 FIPS-204
/// context. Fixed and NUL-free, so `V2_DOMAIN || 0x00 || msg` is unambiguous. Never reuse it for
/// anything but the v2 hybrid.
pub const V2_DOMAIN: &[u8] = b"ember-crypto/hybrid-ed25519-ml-dsa-65-v2";

/// Which hybrid construction: the algorithm id, and how each component's signed bytes are formed.
#[derive(Clone, Copy)]
enum Version {
    V1,
    V2,
}

impl Version {
    fn alg(self) -> &'static str {
        match self {
            Version::V1 => alg::HYBRID_ED25519_ML_DSA_65,
            Version::V2 => alg::HYBRID_ED25519_ML_DSA_65_V2,
        }
    }

    /// The bytes the Ed25519 component signs.
    fn ed_msg(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Version::V1 => msg.to_vec(),
            Version::V2 => {
                let mut m = Vec::with_capacity(V2_DOMAIN.len() + 1 + msg.len());
                m.extend_from_slice(V2_DOMAIN);
                m.push(0x00);
                m.extend_from_slice(msg);
                m
            }
        }
    }

    /// The FIPS-204 context the ML-DSA-65 component signs under.
    fn pq_ctx(self) -> &'static [u8] {
        match self {
            Version::V1 => b"",
            Version::V2 => V2_DOMAIN,
        }
    }
}

/// Ed25519 + ML-DSA-65 robust combiner, **v1**: both components sign the raw message. Each component
/// of a v1 signature is also a valid standalone signature, so a v1 hybrid can be stripped down to its
/// weaker half wherever a component key is trusted on its own. Kept for verifying existing v1
/// signatures; sign new data with [`HybridV2Scheme`].
pub struct HybridScheme;

/// Ed25519 + ML-DSA-65 robust combiner, **v2**: both sign under the hybrid domain [`V2_DOMAIN`];
/// both must verify. The scheme to sign with.
pub struct HybridV2Scheme;

impl SignatureScheme for HybridScheme {
    fn algorithm(&self) -> &'static str {
        Version::V1.alg()
    }
    fn generate(&self) -> Result<Keypair, CryptoError> {
        generate(Version::V1)
    }
    fn sign(&self, secret: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
        sign(Version::V1, secret, msg)
    }
    fn verify(&self, public: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        verify(Version::V1, public, msg, sig)
    }
}

impl SignatureScheme for HybridV2Scheme {
    fn algorithm(&self) -> &'static str {
        Version::V2.alg()
    }
    fn generate(&self) -> Result<Keypair, CryptoError> {
        generate(Version::V2)
    }
    fn sign(&self, secret: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
        sign(Version::V2, secret, msg)
    }
    fn verify(&self, public: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        verify(Version::V2, public, msg, sig)
    }
}

fn generate(v: Version) -> Result<Keypair, CryptoError> {
    let ed = Ed25519Scheme.generate()?;
    let pq = MlDsa65Scheme.generate()?;
    Ok(Keypair {
        public: PublicKey {
            algorithm: v.alg(),
            bytes: lp_pack(&[&ed.public.bytes, &pq.public.bytes]),
        },
        secret: SecretKey {
            algorithm: v.alg(),
            bytes: lp_pack(&[&ed.secret.bytes, &pq.secret.bytes]),
        },
    })
}

fn sign(v: Version, secret: &SecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
    ensure_alg(v, secret.algorithm)?;
    let parts = lp_unpack(&secret.bytes, 2, CryptoError::MalformedKey)?;
    let ed_sk = SecretKey {
        algorithm: alg::ED25519,
        bytes: parts[0].to_vec(),
    };
    let pq_sk = SecretKey {
        algorithm: alg::ML_DSA_65,
        bytes: parts[1].to_vec(),
    };
    let ed_sig = Ed25519Scheme.sign(&ed_sk, &v.ed_msg(msg))?;
    let pq_sig = mldsa::sign_with_ctx(&pq_sk, msg, v.pq_ctx())?;
    Ok(Signature {
        algorithm: v.alg(),
        bytes: lp_pack(&[&ed_sig.bytes, &pq_sig.bytes]),
    })
}

fn verify(v: Version, public: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
    ensure_alg(v, public.algorithm)?;
    ensure_alg(v, sig.algorithm)?;
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
    Ed25519Scheme.verify(&ed_pk, &v.ed_msg(msg), &ed_sig)?;
    mldsa::verify_with_ctx(&pq_pk, msg, &pq_sig, v.pq_ctx())?;
    Ok(())
}

fn ensure_alg(v: Version, algorithm: &str) -> Result<(), CryptoError> {
    if algorithm == v.alg() {
        Ok(())
    } else {
        Err(CryptoError::AlgorithmMismatch {
            expected: v.alg(),
            got: algorithm.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchemeRegistry;

    /// Both versions, for the properties they share.
    fn schemes() -> [&'static dyn SignatureScheme; 2] {
        [&HybridScheme, &HybridV2Scheme]
    }

    fn split(sig: &Signature) -> (Vec<u8>, Vec<u8>) {
        let parts = lp_unpack(&sig.bytes, 2, CryptoError::MalformedSignature).unwrap();
        (parts[0].to_vec(), parts[1].to_vec())
    }

    fn component_keys(kp: &Keypair) -> (PublicKey, PublicKey) {
        let parts = lp_unpack(&kp.public.bytes, 2, CryptoError::MalformedKey).unwrap();
        (
            PublicKey {
                algorithm: alg::ED25519,
                bytes: parts[0].to_vec(),
            },
            PublicKey {
                algorithm: alg::ML_DSA_65,
                bytes: parts[1].to_vec(),
            },
        )
    }

    #[test]
    fn sign_verify_roundtrip() {
        for scheme in schemes() {
            let kp = scheme.generate().unwrap();
            assert_eq!(kp.public.algorithm, scheme.algorithm());
            let sig = scheme.sign(&kp.secret, b"both must hold").unwrap();
            assert_eq!(sig.algorithm, scheme.algorithm());
            assert_eq!(scheme.verify(&kp.public, b"both must hold", &sig), Ok(()));
        }
    }

    #[test]
    fn tampered_message_fails() {
        for scheme in schemes() {
            let kp = scheme.generate().unwrap();
            let sig = scheme.sign(&kp.secret, b"original").unwrap();
            assert_eq!(
                scheme.verify(&kp.public, b"tampered", &sig),
                Err(CryptoError::VerificationFailed)
            );
        }
    }

    #[test]
    fn breaking_either_half_still_fails() {
        // Corrupt one component; the other is untouched and valid. Robust combiner ⇒ overall
        // verification still fails, because BOTH are required.
        for scheme in schemes() {
            for half in 0..2 {
                let kp = scheme.generate().unwrap();
                let sig = scheme.sign(&kp.secret, b"m").unwrap();
                let (mut ed, mut pq) = split(&sig);
                if half == 0 {
                    ed[0] ^= 0x01
                } else {
                    pq[0] ^= 0x01
                }
                let forged = Signature {
                    algorithm: scheme.algorithm(),
                    bytes: lp_pack(&[&ed, &pq]),
                };
                assert_eq!(
                    scheme.verify(&kp.public, b"m", &forged),
                    Err(CryptoError::VerificationFailed),
                    "{} half {half}",
                    scheme.algorithm()
                );
            }
        }
    }

    #[test]
    fn wrong_key_fails() {
        for scheme in schemes() {
            let a = scheme.generate().unwrap();
            let b = scheme.generate().unwrap();
            let sig = scheme.sign(&a.secret, b"m").unwrap();
            assert_eq!(
                scheme.verify(&b.public, b"m", &sig),
                Err(CryptoError::VerificationFailed)
            );
        }
    }

    #[test]
    fn malformed_packing_is_distinguished() {
        for scheme in schemes() {
            let kp = scheme.generate().unwrap();
            let sig = scheme.sign(&kp.secret, b"m").unwrap();
            let bad_pk = PublicKey {
                algorithm: scheme.algorithm(),
                bytes: vec![0u8; 3], // too short to even hold a length prefix
            };
            assert_eq!(
                scheme.verify(&bad_pk, b"m", &sig),
                Err(CryptoError::MalformedKey)
            );
        }
    }

    #[test]
    fn v2_components_lifted_out_do_not_verify_standalone() {
        // The v2 fix: neither component of a v2 hybrid is a valid standalone signature on `msg`
        // under its component key, so a hybrid can't be stripped down to its weaker half.
        let kp = HybridV2Scheme.generate().unwrap();
        let sig = HybridV2Scheme.sign(&kp.secret, b"pay alice 1").unwrap();
        let (ed, pq) = split(&sig);
        let (ed_pk, pq_pk) = component_keys(&kp);
        let ed_sig = Signature {
            algorithm: alg::ED25519,
            bytes: ed,
        };
        let pq_sig = Signature {
            algorithm: alg::ML_DSA_65,
            bytes: pq,
        };
        assert_eq!(
            Ed25519Scheme.verify(&ed_pk, b"pay alice 1", &ed_sig),
            Err(CryptoError::VerificationFailed)
        );
        assert_eq!(
            MlDsa65Scheme.verify(&pq_pk, b"pay alice 1", &pq_sig),
            Err(CryptoError::VerificationFailed)
        );
        // Through the standard registry too, which is how a consumer would try it.
        let reg = SchemeRegistry::standard();
        assert!(reg.verify(&ed_pk, b"pay alice 1", &ed_sig).is_err());
        assert!(reg.verify(&pq_pk, b"pay alice 1", &pq_sig).is_err());
    }

    #[test]
    fn v1_components_are_standalone_signatures() {
        // Pins the v1 weakness the module docs describe (so the docs can't quietly go stale): each
        // v1 component verifies on its own. This is why new data is signed with v2.
        let kp = HybridScheme.generate().unwrap();
        let sig = HybridScheme.sign(&kp.secret, b"m").unwrap();
        let (ed, pq) = split(&sig);
        let (ed_pk, pq_pk) = component_keys(&kp);
        assert_eq!(
            Ed25519Scheme.verify(
                &ed_pk,
                b"m",
                &Signature {
                    algorithm: alg::ED25519,
                    bytes: ed
                }
            ),
            Ok(())
        );
        assert_eq!(
            MlDsa65Scheme.verify(
                &pq_pk,
                b"m",
                &Signature {
                    algorithm: alg::ML_DSA_65,
                    bytes: pq
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn relabelling_between_versions_fails() {
        // Same byte layout, different signed bytes: a v1 signature relabelled as v2 (key too) must
        // not verify, and vice versa. Otherwise v2's domain separation could be sidestepped.
        let pairs: [(&dyn SignatureScheme, &dyn SignatureScheme); 2] = [
            (&HybridScheme, &HybridV2Scheme),
            (&HybridV2Scheme, &HybridScheme),
        ];
        for (from, to) in pairs {
            let kp = from.generate().unwrap();
            let sig = from.sign(&kp.secret, b"m").unwrap();
            let pk = PublicKey {
                algorithm: to.algorithm(),
                bytes: kp.public.bytes.clone(),
            };
            let relabelled = Signature {
                algorithm: to.algorithm(),
                bytes: sig.bytes.clone(),
            };
            assert_eq!(
                to.verify(&pk, b"m", &relabelled),
                Err(CryptoError::VerificationFailed),
                "{} -> {}",
                from.algorithm(),
                to.algorithm()
            );
            // Unrelabelled, the other version refuses on the algorithm id.
            assert!(matches!(
                to.verify(&kp.public, b"m", &sig),
                Err(CryptoError::AlgorithmMismatch { .. })
            ));
        }
    }

    #[test]
    fn standard_registry_dispatches_both_versions() {
        let reg = SchemeRegistry::standard();
        for scheme in schemes() {
            let kp = scheme.generate().unwrap();
            let sig = scheme.sign(&kp.secret, b"m").unwrap();
            assert_eq!(reg.verify(&kp.public, b"m", &sig), Ok(()));
        }
    }

    #[test]
    fn v2_domain_is_a_valid_fips204_context_and_nul_free() {
        // FIPS-204 caps ctx at 255 bytes; the 0x00 separator relies on the domain having no NUL.
        assert!(V2_DOMAIN.len() <= 255);
        assert!(!V2_DOMAIN.contains(&0));
    }
}
