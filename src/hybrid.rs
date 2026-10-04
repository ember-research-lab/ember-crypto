//! hybrid — Ed25519 **and** ML-DSA-65, the migration posture.
//!
//! Both components sign the message; **both must verify**. This is the robust signature combiner:
//! an existential forgery on the hybrid requires forging *both* components, so the hybrid is
//! unforgeable as long as **either** Ed25519 or ML-DSA-65 is. You get classical security today and
//! post-quantum security against "harvest now, forge later" — without betting on which break lands
//! first, and without throwing away Ed25519's decades of scrutiny.
//!
//! Two versions, told apart by algorithm id:
//! - [`HybridV2Scheme`] (`hybrid-ed25519-ml-dsa-65-v2`) — **sign with this one.** With
//!   `H = SHA-256(composite public key bytes)`: Ed25519 signs [`V2_DOMAIN`] `|| 0x00 || H || msg`,
//!   and ML-DSA-65 signs `H || msg` with FIPS-204 context [`V2_DOMAIN`]. Two properties follow:
//!   a component lifted out of a v2 signature is not a valid standalone Ed25519 or ML-DSA-65
//!   signature on `msg` (no stripping a hybrid down to its weaker half), and components from two
//!   different hybrid keys can't be recombined under a mixed key (both are bound to one key pair).
//! - [`HybridScheme`] (`hybrid-ed25519-ml-dsa-65`, v1) — both components sign the raw `msg` with no
//!   domain, so each component of a v1 signature *is* a valid standalone signature. Verify-only:
//!   existing v1 signatures keep verifying, and its `sign` refuses.
//!
//! Key and signature bytes are the two components packed length-prefixed (`ed25519 || ml-dsa-65`) via
//! [`lp_pack`](crate::lp_pack) — unambiguous, and the same packer/unpacker so they can't drift. The
//! layout is the same in both versions; only the algorithm id and the signed bytes differ, and the
//! algorithm id on every key and signature keeps them apart (relabelling a v1 signature as v2 fails
//! verification, because v2 checks the domain-separated bytes).

use crate::{
    alg, content_hash, ed25519, ed25519::Ed25519Scheme, lp_pack, lp_unpack, mldsa,
    mldsa::MlDsa65Scheme, CryptoError, Keypair, PublicKey, SecretKey, Signature, SignatureScheme,
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

    /// The bytes the ML-DSA-65 component signs: v1 the raw `msg`; v2 `SHA-256(composite public key)
    /// || msg`, binding the signature to this exact (Ed25519, ML-DSA-65) key pair.
    fn pq_msg(self, composite_pk: &[u8], msg: &[u8]) -> Vec<u8> {
        match self {
            Version::V1 => msg.to_vec(),
            Version::V2 => {
                let mut m = Vec::with_capacity(32 + msg.len());
                m.extend_from_slice(&content_hash(composite_pk));
                m.extend_from_slice(msg);
                m
            }
        }
    }

    /// The bytes the Ed25519 component signs: v1 the raw `msg`; v2 `V2_DOMAIN || 0x00 ||
    /// SHA-256(composite public key) || msg`.
    fn ed_msg(self, composite_pk: &[u8], msg: &[u8]) -> Vec<u8> {
        match self {
            Version::V1 => msg.to_vec(),
            Version::V2 => {
                let bound = self.pq_msg(composite_pk, msg);
                let mut m = Vec::with_capacity(V2_DOMAIN.len() + 1 + bound.len());
                m.extend_from_slice(V2_DOMAIN);
                m.push(0x00);
                m.extend_from_slice(&bound);
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
/// weaker half wherever a component key is trusted on its own. **Verify-only**: `sign` refuses, so
/// existing v1 signatures keep verifying but no new ones are made. Sign with [`HybridV2Scheme`];
/// generate fresh v2 keys rather than relabelling v1 keys (the bytes are the same layout).
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
    /// Refuses: v1 is verify-only, so no new liftable signatures are made. Sign with
    /// [`HybridV2Scheme`].
    fn sign(&self, _secret: &SecretKey, _msg: &[u8]) -> Result<Signature, CryptoError> {
        Err(CryptoError::Sign(
            "hybrid v1 is verify-only; sign with hybrid-ed25519-ml-dsa-65-v2",
        ))
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
    // The composite public key, derived from the secret halves (same packing as `generate`), so
    // v2 binds it into both signed messages.
    let composite_pk = lp_pack(&[
        &ed25519::public_from_secret(&ed_sk)?,
        &mldsa::public_from_secret(&pq_sk)?,
    ]);
    let ed_sig = Ed25519Scheme.sign(&ed_sk, &v.ed_msg(&composite_pk, msg))?;
    let pq_sig = mldsa::sign_with_ctx(&pq_sk, &v.pq_msg(&composite_pk, msg), v.pq_ctx())?;
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
    Ed25519Scheme.verify(&ed_pk, &v.ed_msg(&public.bytes, msg), &ed_sig)?;
    mldsa::verify_with_ctx(&pq_pk, &v.pq_msg(&public.bytes, msg), &pq_sig, v.pq_ctx())?;
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

    /// Both versions, for the properties they share. v1's public `sign` refuses, so tests make v1
    /// signatures through the internal `sign` (as an old signer would have).
    fn schemes() -> [(Version, &'static dyn SignatureScheme); 2] {
        [(Version::V1, &HybridScheme), (Version::V2, &HybridV2Scheme)]
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
        for (v, scheme) in schemes() {
            let kp = scheme.generate().unwrap();
            assert_eq!(kp.public.algorithm, scheme.algorithm());
            let sig = sign(v, &kp.secret, b"both must hold").unwrap();
            assert_eq!(sig.algorithm, scheme.algorithm());
            assert_eq!(scheme.verify(&kp.public, b"both must hold", &sig), Ok(()));
        }
    }

    #[test]
    fn tampered_message_fails() {
        for (v, scheme) in schemes() {
            let kp = scheme.generate().unwrap();
            let sig = sign(v, &kp.secret, b"original").unwrap();
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
        for (v, scheme) in schemes() {
            for half in 0..2 {
                let kp = scheme.generate().unwrap();
                let sig = sign(v, &kp.secret, b"m").unwrap();
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
        for (v, scheme) in schemes() {
            let a = scheme.generate().unwrap();
            let b = scheme.generate().unwrap();
            let sig = sign(v, &a.secret, b"m").unwrap();
            assert_eq!(
                scheme.verify(&b.public, b"m", &sig),
                Err(CryptoError::VerificationFailed)
            );
        }
    }

    #[test]
    fn malformed_packing_is_distinguished() {
        for (v, scheme) in schemes() {
            let kp = scheme.generate().unwrap();
            let sig = sign(v, &kp.secret, b"m").unwrap();
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
        let sig = sign(Version::V1, &kp.secret, b"m").unwrap();
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
        let pairs: [(Version, &dyn SignatureScheme, &dyn SignatureScheme); 2] = [
            (Version::V1, &HybridScheme, &HybridV2Scheme),
            (Version::V2, &HybridV2Scheme, &HybridScheme),
        ];
        for (v, from, to) in pairs {
            let kp = from.generate().unwrap();
            let sig = sign(v, &kp.secret, b"m").unwrap();
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
        for (v, scheme) in schemes() {
            let kp = scheme.generate().unwrap();
            let sig = sign(v, &kp.secret, b"m").unwrap();
            assert_eq!(reg.verify(&kp.public, b"m", &sig), Ok(()));
        }
    }

    #[test]
    fn v2_domain_is_a_valid_fips204_context_and_nul_free() {
        // FIPS-204 caps ctx at 255 bytes; the 0x00 separator relies on the domain having no NUL.
        assert!(V2_DOMAIN.len() <= 255);
        assert!(!V2_DOMAIN.contains(&0));
    }

    #[test]
    fn v1_sign_refuses() {
        let kp = HybridScheme.generate().unwrap();
        assert!(matches!(
            HybridScheme.sign(&kp.secret, b"m"),
            Err(CryptoError::Sign(_))
        ));
    }

    #[test]
    fn v2_signed_bytes_are_pinned() {
        // Rebuild the signed bytes independently of `Version` (literal domain, SHA-256 of the packed
        // public key) and check each component against them. Changing the construction or the
        // domain by accident breaks this test, not every stored v2 signature.
        const DOMAIN: &[u8] = b"ember-crypto/hybrid-ed25519-ml-dsa-65-v2";
        let kp = HybridV2Scheme.generate().unwrap();
        let sig = HybridV2Scheme.sign(&kp.secret, b"m").unwrap();
        let (ed, pq) = split(&sig);
        let (ed_pk, pq_pk) = component_keys(&kp);
        let h = content_hash(&kp.public.bytes);
        let mut ed_msg = DOMAIN.to_vec();
        ed_msg.push(0x00);
        ed_msg.extend_from_slice(&h);
        ed_msg.extend_from_slice(b"m");
        let mut pq_msg = h.to_vec();
        pq_msg.extend_from_slice(b"m");
        assert_eq!(
            Ed25519Scheme.verify(
                &ed_pk,
                &ed_msg,
                &Signature {
                    algorithm: alg::ED25519,
                    bytes: ed
                }
            ),
            Ok(())
        );
        assert_eq!(
            mldsa::verify_with_ctx(
                &pq_pk,
                &pq_msg,
                &Signature {
                    algorithm: alg::ML_DSA_65,
                    bytes: pq
                },
                DOMAIN
            ),
            Ok(())
        );
    }

    #[test]
    fn stored_v2_vector_keeps_verifying() {
        // A v2 signature generated once (2026-10-04) and committed. If this ever fails, stored v2
        // signatures in consumers would stop verifying: the change is a new version, not an edit.
        let mut lines = include_str!("testdata/hybrid_v2_vector.txt").lines();
        let mut field = |name: &str| {
            let line = lines.next().unwrap();
            let (k, v) = line.split_once('=').unwrap();
            assert_eq!(k, name);
            v.to_string()
        };
        let pk = PublicKey {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65_V2,
            bytes: hex_decode(&field("public_key")),
        };
        let msg = field("message");
        let sig = Signature {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65_V2,
            bytes: hex_decode(&field("signature")),
        };
        assert_eq!(HybridV2Scheme.verify(&pk, msg.as_bytes(), &sig), Ok(()));
        assert_eq!(
            HybridV2Scheme.verify(&pk, b"other message", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn v2_components_from_two_keys_do_not_recombine() {
        // A and B both sign m. Under v1 the mixed key (edA, pqB) with (edA_sig, pqB_sig) would
        // verify; v2 binds each component to its own composite key, so the mix fails.
        let a = HybridV2Scheme.generate().unwrap();
        let b = HybridV2Scheme.generate().unwrap();
        let (a_ed, _) = split(&HybridV2Scheme.sign(&a.secret, b"m").unwrap());
        let (_, b_pq) = split(&HybridV2Scheme.sign(&b.secret, b"m").unwrap());
        let (a_ed_pk, _) = component_keys(&a);
        let (_, b_pq_pk) = component_keys(&b);
        let mixed_pk = PublicKey {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65_V2,
            bytes: lp_pack(&[&a_ed_pk.bytes, &b_pq_pk.bytes]),
        };
        let mixed_sig = Signature {
            algorithm: alg::HYBRID_ED25519_ML_DSA_65_V2,
            bytes: lp_pack(&[&a_ed, &b_pq]),
        };
        assert_eq!(
            HybridV2Scheme.verify(&mixed_pk, b"m", &mixed_sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn composite_key_derived_from_secret_matches_generated() {
        // `sign` binds the composite key it derives from the secret halves; it must be byte-equal
        // to the public key `generate` returned, or honest v2 signatures would never verify.
        let kp = HybridV2Scheme.generate().unwrap();
        let parts = lp_unpack(&kp.secret.bytes, 2, CryptoError::MalformedKey).unwrap();
        let ed_sk = SecretKey {
            algorithm: alg::ED25519,
            bytes: parts[0].to_vec(),
        };
        let pq_sk = SecretKey {
            algorithm: alg::ML_DSA_65,
            bytes: parts[1].to_vec(),
        };
        let derived = lp_pack(&[
            &ed25519::public_from_secret(&ed_sk).unwrap(),
            &mldsa::public_from_secret(&pq_sk).unwrap(),
        ]);
        assert_eq!(derived, kp.public.bytes);
    }

    #[test]
    #[ignore = "generator for src/testdata/hybrid_v2_vector.txt; run once, never regenerate"]
    fn print_v2_vector() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let kp = HybridV2Scheme.generate().unwrap();
        let msg = "ember-crypto hybrid v2 stored vector";
        let sig = HybridV2Scheme.sign(&kp.secret, msg.as_bytes()).unwrap();
        println!("public_key={}", hex(&kp.public.bytes));
        println!("message={msg}");
        println!("signature={}", hex(&sig.bytes));
    }
}
