# ember-crypto

The org's single **sign / verify / hash** surface, behind a crypto-agility interface. One place owns
the cryptography every Ember consumer trusts — cortex (ledger block signing), ember-graph (provenance
envelopes), the SMB platform (per-agent action signatures) — so the algorithm choice is made once,
named explicitly, and migratable without a flag day.

## The rule: the algorithm is always named, never hardcoded

Every `Signature` and key carries its algorithm id. A `SchemeRegistry` dispatches verification on that
id and can hold several algorithms at once, so an **Ed25519 → ML-DSA migration is additive**: old
signatures keep verifying while new ones use the post-quantum scheme. No call site ever assumes a
single algorithm.

## Algorithms

| Scheme | id | Notes |
|---|---|---|
| `Ed25519Scheme` | `ed25519` | Classical EdDSA. Always available. Key ids are **byte-identical to cortex** (`compute_key_id`), so identities line up across the ledger. |
| `MlDsa65Scheme` *(feature `pqc`)* | `ml-dsa-65` | ML-DSA-65 / NIST **FIPS-204**, post-quantum. Pure-Rust (`fips204`) — no C, no aws-lc-rs. |
| `HybridScheme` *(feature `pqc`)* | `hybrid-ed25519-ml-dsa-65` | Ed25519 **and** ML-DSA-65; both sign, **both must verify**. |

### Why hybrid is the migration posture

The hybrid is the **robust combiner**: an existential forgery requires forging *both* components, so
it stays unforgeable as long as **either** Ed25519 or ML-DSA-65 is. You get classical security today
and protection against "harvest now, forge later" — without betting on which break lands first, and
without discarding Ed25519's decades of scrutiny. Sign hybrid now; when one side is eventually retired
the registry just stops offering it, and verification of old envelopes is unaffected.

## What this crate is *not*

It **never persists, escrows, or rotates key material** — custody is the consumer's job (ember-vault).
A `SecretKey` exists only for the span of a sign call and is zeroized on drop, debug-redacted. This
crate signs, verifies, and hashes; it does **not** decide *who* is trusted — that identity/trust layer
lives in the consumer (e.g. ember-graph's `VerifierRegistry`).

## Hashing

`content_hash` and `key_id` are **SHA-256** — the org's hash everywhere, cortex's ledger included
(despite older docs mentioning BLAKE3, every block hash is SHA-256). `key_id` reproduces cortex's
`compute_key_id` exactly: the first 6 hex chars (uppercase) of `SHA-256(public_key_bytes)`.

## Features

- `pqc` *(default)* — pulls in ML-DSA-65 + the hybrid scheme (via `fips204`).
- A consumer that must stay classical (cortex, on the inviolable substrate) builds with
  `default-features = false` and gets Ed25519 only — no PQC code compiled in.

```toml
# post-quantum-capable consumer (ember-graph, SMB platform)
ember-crypto = { path = "../ember-crypto" }

# classical-only consumer (cortex substrate compat)
ember-crypto = { path = "../ember-crypto", default-features = false }
```

## Usage

```rust
use ember_crypto::{SchemeRegistry, SignatureScheme, HybridScheme, key_id};

let kp = HybridScheme.generate()?;
let sig = HybridScheme.sign(&kp.secret, b"agent action payload")?;

// Verify without knowing the algorithm in advance — the registry dispatches on the signature.
let registry = SchemeRegistry::standard();
registry.verify(&kp.public, b"agent action payload", &sig)?;

let id = key_id(&kp.public); // short, cortex-compatible identity tag
# Ok::<(), ember_crypto::CryptoError>(())
```

## Status

`#![forbid(unsafe_code)]` (own code), zero C dependencies, clippy `-D warnings` clean across
`default` / `--no-default-features` / `--all-features`, fmt clean. Tests cover sign/verify roundtrips,
tamper/wrong-key/flipped-byte rejection, malformed-vs-failed distinction, cortex key-id parity, the
crypto-agility registry (fail-closed on unknown algorithm), and — for the hybrid — that corrupting
**either** component alone still fails verification.
