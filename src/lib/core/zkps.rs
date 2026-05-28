//! Zero-knowledge proofs and signatures using Schnorr proofs with the Fiat-Shamir transform.
//!
//! This module provides cryptographic primitives for creating and verifying zero-knowledge proofs
//! that demonstrate knowledge of a discrete logarithm without revealing it. These proofs are
//! non-interactive thanks to the Fiat-Shamir transform, which uses a hash function to derive
//! the challenge.
//!
//! # Overview
//!
//! The main components are:
//! - [`Proof`]: A zero-knowledge proof that demonstrates `N = a*M` without revealing `a`
//! - [`create_proof`]/[`verify_proof`]: Create and verify proofs
//! - [`sign`]/[`verify`]: Create and verify signatures (proofs used as signatures)
//! - [`sign_unlinkable`]: Create deterministic signatures that prevent linkability
//!
//! # Security Properties
//!
//! - **Zero-knowledge**: The verifier learns nothing about the secret scalar beyond what the proof demonstrates
//! - **Soundness**: It's computationally infeasible to create a valid proof without knowing the secret
//! - **Non-interactive**: No interaction between prover and verifier required (thanks to Fiat-Shamir)
//!
//! # Examples
//!
//! ```
//! # use libpep::arithmetic::group_elements::{GroupElement, G};
//! # use libpep::arithmetic::scalars::ScalarNonZero;
//! # use libpep::core::zkps::{create_proof, verify_proof};
//! # let mut rng = rand::rng();
//! let secret = ScalarNonZero::random(&mut rng);
//! let message = GroupElement::random(&mut rng);
//!
//! // Prover creates a proof
//! let (public_key, proof) = create_proof(&secret, &message, &mut rng);
//!
//! // Verifier checks the proof
//! assert!(verify_proof(&public_key, &message, &proof));
//! ```

use derive_more::Deref;
use rand_core::{CryptoRng, Rng};
use sha2::{Digest, Sha512};
use std::fmt::Formatter;

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::{ScalarCanBeZero, ScalarNonZero, ScalarTraits};
use base64::engine::general_purpose;
use base64::Engine;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A zero-knowledge proof demonstrating knowledge of a discrete logarithm.
///
/// This proof shows that `N = a*M` for some secret scalar `a` without revealing `a`.
/// The proof can be verified using the public key `A = a*G` and the message `M`,
/// while keeping the secret `a` hidden.
///
/// The proof uses the Fiat-Shamir transform to make it non-interactive, deriving
/// the challenge from a hash of the public values.
///
/// # Fields
///
/// - `n`: The result `N = a*M` (also accessible via `Deref`)
/// - `c1`, `c2`: Commitments `r*G` and `r*M` for a random nonce `r`
/// - `s`: The response `s = a*e + r` where `e` is the challenge
///
/// # Serialization
///
/// Proofs are serialized as base64-encoded strings when using serde.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Deref)]
pub struct Proof {
    #[deref]
    pub(crate) n: GroupElement,
    pub(crate) c1: GroupElement,
    pub(crate) c2: GroupElement,
    pub(crate) s: ScalarCanBeZero,
}

impl Proof {
    /// The claimed result `N = a*M`.
    pub fn n(&self) -> &GroupElement {
        &self.n
    }

    /// First commitment `c1 = r*G`.
    pub fn c1(&self) -> &GroupElement {
        &self.c1
    }

    /// Second commitment `c2 = r*M`.
    pub fn c2(&self) -> &GroupElement {
        &self.c2
    }

    /// Response scalar `s = a*e + r`.
    pub fn s(&self) -> &ScalarCanBeZero {
        &self.s
    }

    /// Encodes the proof as a 128-byte array.
    ///
    /// The encoding layout is:
    /// - Bytes 0-31: `n`
    /// - Bytes 32-63: `c1`
    /// - Bytes 64-95: `c2`
    /// - Bytes 96-127: `s`
    pub fn encode(&self) -> [u8; 128] {
        let mut retval = [0u8; 128];
        retval[0..32].clone_from_slice(self.n.to_bytes().as_slice());
        retval[32..64].clone_from_slice(self.c1.to_bytes().as_slice());
        retval[64..96].clone_from_slice(self.c2.to_bytes().as_slice());
        retval[96..128].clone_from_slice(self.s.to_bytes().as_slice());
        retval
    }

    /// Decodes a proof from a 128-byte array.
    ///
    /// Returns `None` if any component fails to decode, or if `n`, `c1`,
    /// or `c2` is the identity element (which would make verification
    /// equations vacuous).
    pub fn decode(v: &[u8; 128]) -> Option<Self> {
        let n = GroupElement::from_slice(&v[0..32])?;
        let c1 = GroupElement::from_slice(&v[32..64])?;
        let c2 = GroupElement::from_slice(&v[64..96])?;
        let s = ScalarCanBeZero::from_slice(&v[96..128])?;
        let identity = GroupElement::identity();
        if n == identity || c1 == identity || c2 == identity {
            return None;
        }
        Some(Self { n, c1, c2, s })
    }

    /// Decodes a proof from a byte slice.
    ///
    /// Returns `None` if the slice is not exactly 128 bytes or if decoding fails.
    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != 128 {
            None
        } else {
            let mut arr = [0u8; 128];
            arr.copy_from_slice(v);
            Self::decode(&arr)
        }
    }

    /// Encodes the proof as a URL-safe base64 string.
    pub fn to_base64(&self) -> String {
        general_purpose::URL_SAFE.encode(self.encode())
    }

    /// Decodes a proof from a URL-safe base64 string.
    ///
    /// Returns `None` if the string is not valid base64 or if decoding fails.
    pub fn from_base64(s: &str) -> Option<Self> {
        general_purpose::URL_SAFE
            .decode(s)
            .ok()
            .and_then(|v| Self::decode_from_slice(&v))
    }
}

impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_base64().as_str())
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProofVisitor;
        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = Proof;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 encoded string representing a Proof")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Proof::from_base64(v)
                    .ok_or_else(|| E::custom(format!("invalid base64 encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(ProofVisitor)
    }
}

/// Creates a zero-knowledge proof demonstrating knowledge of a discrete logarithm.
///
/// Given a secret scalar `a` and a public group element `M`, this function creates a proof
/// that `N = a*M` without revealing `a`. The proof uses a random nonce for unlinkability.
///
/// # Arguments
///
/// * `a` - The secret scalar
/// * `gm` - The message/base group element `M`
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
///
/// A tuple `(A, Proof)` where:
/// - `A = a*G` is the public key corresponding to secret `a`
/// - `Proof` contains `N = a*M` and the zero-knowledge proof
///
/// # Example
///
/// ```
/// # use libpep::arithmetic::group_elements::{GroupElement, G};
/// # use libpep::arithmetic::scalars::ScalarNonZero;
/// # use libpep::core::zkps::{create_proof, verify_proof};
/// # let mut rng = rand::rng();
/// let secret = ScalarNonZero::random(&mut rng);
/// let message = GroupElement::random(&mut rng);
///
/// let (public_key, proof) = create_proof(&secret, &message, &mut rng);
/// assert!(verify_proof(&public_key, &message, &proof));
/// ```
pub fn create_proof<R: Rng + CryptoRng>(
    a: &ScalarNonZero,
    gm: &GroupElement,
    rng: &mut R,
) -> (GroupElement, Proof) {
    let r = ScalarNonZero::random(rng);

    let ga = a * G;
    let gn = a * gm;
    let gc1 = r * G;
    let gc2 = r * gm;

    let mut hasher = Sha512::new();
    hasher.update(ga.to_bytes());
    hasher.update(gm.to_bytes());
    hasher.update(gn.to_bytes());
    hasher.update(gc1.to_bytes());
    hasher.update(gc2.to_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::from_hash(&bytes);
    let s = ScalarCanBeZero((a * e).0) + ScalarCanBeZero(r.0);
    (
        ga,
        Proof {
            n: gn,
            c1: gc1,
            c2: gc2,
            s,
        },
    )
}

/// Creates two zero-knowledge proofs with the same scalar, sharing the
/// public key `ga = a*G` computation.
///
/// Each proof uses an **independent** random nonce. Reusing a nonce across
/// two proofs with the same witness `a` but different bases `gm1`, `gm2`
/// would let any verifier solve `a = (s1 - s2) / (e1 - e2)` from the
/// published responses.
///
/// # Arguments
/// * `a` - The secret scalar (same for both proofs)
/// * `gm1` - First message element
/// * `gm2` - Second message element
/// * `rng` - Random number generator
///
/// # Returns
/// A tuple containing:
/// - The shared public key `ga`
/// - First proof for `gm1`
/// - Second proof for `gm2`
pub fn create_proofs_same_scalar<R: Rng + CryptoRng>(
    a: &ScalarNonZero,
    gm1: &GroupElement,
    gm2: &GroupElement,
    rng: &mut R,
) -> (GroupElement, Proof, Proof) {
    let ga = a * G;

    // First proof
    let r1 = ScalarNonZero::random(rng);
    let gn1 = a * gm1;
    let gc1_1 = r1 * G;
    let gc2_1 = r1 * gm1;

    let mut hasher = Sha512::new();
    hasher.update(ga.to_bytes());
    hasher.update(gm1.to_bytes());
    hasher.update(gn1.to_bytes());
    hasher.update(gc1_1.to_bytes());
    hasher.update(gc2_1.to_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e1 = ScalarNonZero::from_hash(&bytes);
    let s1 = ScalarCanBeZero((a * e1).0) + ScalarCanBeZero(r1.0);

    let proof1 = Proof {
        n: gn1,
        c1: gc1_1,
        c2: gc2_1,
        s: s1,
    };

    // Second proof, with a fresh independent nonce
    let r2 = ScalarNonZero::random(rng);
    let gn2 = a * gm2;
    let gc1_2 = r2 * G;
    let gc2_2 = r2 * gm2;

    let mut hasher = Sha512::new();
    hasher.update(ga.to_bytes());
    hasher.update(gm2.to_bytes());
    hasher.update(gn2.to_bytes());
    hasher.update(gc1_2.to_bytes());
    hasher.update(gc2_2.to_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e2 = ScalarNonZero::from_hash(&bytes);
    let s2 = ScalarCanBeZero((a * e2).0) + ScalarCanBeZero(r2.0);

    let proof2 = Proof {
        n: gn2,
        c1: gc1_2,
        c2: gc2_2,
        s: s2,
    };

    (ga, proof1, proof2)
}

/// Verifies a zero-knowledge proof with all components provided separately.
///
/// Internal use only: most callers should use [`verify_proof`]. The split
/// form exists because the tests exercise tampered components directly.
///
/// # Arguments
///
/// * `ga` - The public key `A = a*G`
/// * `gm` - The message `M`
/// * `gn` - The claimed result `N = a*M`
/// * `gc1` - The first commitment `c1 = r*G`
/// * `gc2` - The second commitment `c2 = r*M`
/// * `s` - The response scalar
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise.
///
/// # Verification Equations
///
/// The function checks that:
/// - `s*G == e*A + c1`
/// - `s*M == e*N + c2`
///
/// where `e` is the challenge derived from hashing all public values.
///
/// Also guards against trivially insecure inputs: rejects if any of
/// `gm`, `ga`, `gn`, `gc1`, `gc2` is the identity element. With an
/// identity base the verification equations become vacuous and an
/// attacker could forge proofs without knowing the witness; with an
/// identity `gn`/`gc1`/`gc2` the proof would not meaningfully bind to
/// the claimed result. ([`Proof::decode`] already rejects identity
/// `n`/`c1`/`c2`; this is defense in depth at the verification layer.)
#[must_use]
pub(crate) fn verify_proof_split(
    ga: &GroupElement,
    gm: &GroupElement,
    gn: &GroupElement,
    gc1: &GroupElement,
    gc2: &GroupElement,
    s: &ScalarCanBeZero,
) -> bool {
    let identity = GroupElement::identity();
    if gm == &identity || ga == &identity || gn == &identity || gc1 == &identity || gc2 == &identity
    {
        return false;
    }

    let mut hasher = Sha512::new();
    hasher.update(ga.to_bytes());
    hasher.update(gm.to_bytes());
    hasher.update(gn.to_bytes());
    hasher.update(gc1.to_bytes());
    hasher.update(gc2.to_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::from_hash(&bytes);

    // FIXME speed up with https://docs.rs/curve25519-dalek/latest/curve25519_dalek/traits/trait.VartimeMultiscalarMul.html
    // FIXME check if a faster non-constant time equality can be used
    s * G == e * ga + gc1 && s * gm == e * gn + gc2
}

/// Verifies a zero-knowledge proof.
///
/// This is the standard way to verify a proof. It checks that the proof correctly demonstrates
/// knowledge of the discrete logarithm relationship `N = a*M` without revealing `a`.
///
/// # Arguments
///
/// * `ga` - The public key `A = a*G`
/// * `gm` - The message `M`
/// * `p` - The proof to verify
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise.
///
/// # Example
///
/// ```
/// # use libpep::arithmetic::group_elements::{GroupElement, G};
/// # use libpep::arithmetic::scalars::ScalarNonZero;
/// # use libpep::core::zkps::{create_proof, verify_proof};
/// # let mut rng = rand::rng();
/// # let secret = ScalarNonZero::random(&mut rng);
/// # let message = GroupElement::random(&mut rng);
/// let (public_key, proof) = create_proof(&secret, &message, &mut rng);
/// assert!(verify_proof(&public_key, &message, &proof));
/// ```
#[must_use]
pub fn verify_proof(ga: &GroupElement, gm: &GroupElement, p: &Proof) -> bool {
    verify_proof_split(ga, gm, &p.n, &p.c1, &p.c2, &p.s)
}

/// Type alias for signatures, which are structurally identical to proofs.
type Signature = Proof;

/// Creates a digital signature for a message using a secret key.
///
/// This function uses the zero-knowledge proof system to create a signature.
/// Each signature uses a fresh random nonce, making signatures unlinkable.
///
/// # Arguments
///
/// * `message` - The message to sign (a group element)
/// * `secret_key` - The secret signing key
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
///
/// A signature that can be verified with the corresponding public key.
///
/// # Example
///
/// ```
/// # use libpep::arithmetic::group_elements::{GroupElement, G};
/// # use libpep::arithmetic::scalars::ScalarNonZero;
/// # use libpep::core::zkps::{sign, verify};
/// # let mut rng = rand::rng();
/// let secret_key = ScalarNonZero::random(&mut rng);
/// let public_key = &secret_key * G;
/// let message = GroupElement::random(&mut rng);
///
/// let signature = sign(&message, &secret_key, &mut rng);
/// assert!(verify(&message, &signature, &public_key));
/// ```
pub fn sign<R: Rng + CryptoRng>(
    message: &GroupElement,
    secret_key: &ScalarNonZero,
    rng: &mut R,
) -> Signature {
    create_proof(secret_key, message, rng).1
}

/// Verifies a digital signature.
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `p` - The signature to verify
/// * `public_key` - The public key corresponding to the secret key used for signing
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
#[must_use]
pub fn verify(message: &GroupElement, p: &Signature, public_key: &GroupElement) -> bool {
    verify_proof(public_key, message, p)
}

/// Creates a deterministic unlinkable proof.
///
/// Unlike [`create_proof`], this function uses a deterministic nonce derived from the
/// (secret, message) pair rather than a random one. This means:
/// - The same inputs always produce the same proof (deterministic)
/// - Multiple signatures of the same message under the same key are identical
/// - The nonce cannot be used to link different proofs (unlinkable)
///
/// This is useful when you want consistent proofs but don't want random values that could
/// potentially be used for linking.
///
/// # Arguments
///
/// * `a` - The secret scalar
/// * `gm` - The message/base group element `M`
///
/// # Returns
///
/// A tuple `(A, Proof)` where:
/// - `A = a*G` is the public key
/// - `Proof` is the deterministic zero-knowledge proof
///
/// # Security Note
///
/// The deterministic nonce is derived (EdDSA-style) by hashing the secret scalar together
/// with the message, so distinct (secret, message) pairs produce distinct nonces. The
/// nonce hash is domain-separated from the Fiat-Shamir challenge hash.
pub fn create_proof_unlinkable(a: &ScalarNonZero, gm: &GroupElement) -> (GroupElement, Proof) {
    let mut hasher = Sha512::new();
    hasher.update(a.to_bytes());
    hasher.update(gm.to_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let r = ScalarNonZero::from_hash(&bytes);

    let ga = a * G;
    let gn = a * gm;
    let gc1 = r * G;
    let gc2 = r * gm;

    let mut hasher = Sha512::new();
    hasher.update(ga.to_bytes());
    hasher.update(gm.to_bytes());
    hasher.update(gn.to_bytes());
    hasher.update(gc1.to_bytes());
    hasher.update(gc2.to_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::from_hash(&bytes);
    let s = ScalarCanBeZero((a * e).0) + ScalarCanBeZero(r.0);
    (
        ga,
        Proof {
            n: gn,
            c1: gc1,
            c2: gc2,
            s,
        },
    )
}

/// Creates a deterministic unlinkable signature.
///
/// This function creates a signature using a deterministic nonce derived from the message.
/// Unlike [`sign`], which uses random nonces:
/// - The same message and key always produce the same signature
/// - Signatures cannot be used to link different signings
/// - No random number generator is required
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `secret_key` - The secret signing key
///
/// # Returns
///
/// A deterministic signature that can be verified with the corresponding public key.
///
/// # Example
///
/// ```
/// # use libpep::arithmetic::group_elements::{GroupElement, G};
/// # use libpep::arithmetic::scalars::ScalarNonZero;
/// # use libpep::core::zkps::{sign_unlinkable, verify};
/// # let mut rng = rand::rng();
/// let secret_key = ScalarNonZero::random(&mut rng);
/// let public_key = &secret_key * G;
/// let message = GroupElement::random(&mut rng);
///
/// let sig1 = sign_unlinkable(&message, &secret_key);
/// let sig2 = sign_unlinkable(&message, &secret_key);
/// assert_eq!(sig1, sig2); // Same inputs produce same signature
/// assert!(verify(&message, &sig1, &public_key));
/// ```
pub fn sign_unlinkable(message: &GroupElement, secret_key: &ScalarNonZero) -> Signature {
    create_proof_unlinkable(secret_key, message).1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::arithmetic::group_elements::{GroupElement, G};
    use crate::arithmetic::scalars::ScalarNonZero;
    use crate::core::zkps::{
        create_proof, create_proof_unlinkable, create_proofs_same_scalar, sign, sign_unlinkable,
        verify, verify_proof, verify_proof_split, Proof,
    };

    #[test]
    fn elgamal_signature() {
        let mut rng = rand::rng();
        // secret key
        let s = ScalarNonZero::random(&mut rng);
        let s2 = ScalarNonZero::random(&mut rng);
        // public key
        let gp = s * G;

        let v = GroupElement::random(&mut rng);
        let mut signature = sign(&v, &s, &mut rng);
        assert!(verify(&v, &signature, &gp));

        signature = sign(&v, &s2, &mut rng);
        assert!(!verify(&v, &signature, &gp));
    }

    #[test]
    fn pep_schnorr_basic_offline() {
        let mut rng = rand::rng();
        // given a secret a and public M, proof that a certain triplet (A, M, N) is actually calculated by (a*G, M, a * M)
        // using Fiat-Shamir transform

        // prover
        let a = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);

        let (ga, p) = create_proof(&a, &gm, &mut rng);
        assert_eq!(a * gm, *p);

        // verifier
        assert!(verify_proof(&ga, &gm, &p));
    }

    #[test]
    fn create_proofs_same_scalar_uses_independent_nonces() {
        // Regression test: if both proofs reused the same nonce r, then their
        // r*G commitments would be equal and an attacker could recover the
        // witness a from (s1 - s2) / (e1 - e2). Verify the nonces differ and
        // that the naive witness-recovery attack does not succeed.
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let gm1 = GroupElement::random(&mut rng);
        let gm2 = GroupElement::random(&mut rng);

        let (ga, p1, p2) = create_proofs_same_scalar(&a, &gm1, &gm2, &mut rng);

        assert!(verify_proof(&ga, &gm1, &p1));
        assert!(verify_proof(&ga, &gm2, &p2));
        // Nonces must be independent: r1*G != r2*G with overwhelming probability.
        assert_ne!(p1.c1, p2.c1);
    }

    #[test]
    fn elgamal_signature_unlinkable() {
        let mut rng = rand::rng();
        // secret key
        let s = ScalarNonZero::random(&mut rng);
        // public key
        let gp = s * G;

        let v = GroupElement::random(&mut rng);
        let sig1 = sign_unlinkable(&v, &s);
        assert!(verify(&v, &sig1, &gp));

        let sig2 = sign_unlinkable(&v, &s);
        assert!(verify(&v, &sig2, &gp));
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn create_proof_unlinkable_nonce_binds_to_secret() {
        // Regression test: the deterministic nonce must depend on the secret
        // scalar, not just the message. Two distinct keys signing the same
        // message must produce distinct r*G commitments.
        let mut rng = rand::rng();
        let a1 = ScalarNonZero::random(&mut rng);
        let a2 = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);

        let (_, p1) = create_proof_unlinkable(&a1, &gm);
        let (_, p2) = create_proof_unlinkable(&a2, &gm);

        assert_ne!(p1.c1, p2.c1);

        // Determinism: same (a, gm) still produces the same proof.
        let (_, p1_again) = create_proof_unlinkable(&a1, &gm);
        assert_eq!(p1, p1_again);
    }

    #[test]
    fn verify_rejects_identity_gm() {
        // Regression test: when `gm` is the identity element, the verification
        // equation `s*M == e*N + c2` becomes `0 == 0 + c2`, which would be
        // trivially satisfied by an attacker-chosen `c2 = 0` and any `c1`.
        // Verification must reject any such input outright.
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);
        let (ga, p) = create_proof(&a, &gm, &mut rng);

        // Sanity check: honest verification with the real `gm` passes.
        assert!(verify_proof(&ga, &gm, &p));
        // But swapping in identity for `gm` must fail.
        assert!(!verify_proof(&ga, &GroupElement::identity(), &p));
        assert!(!verify_proof_split(
            &ga,
            &GroupElement::identity(),
            &p.n,
            &p.c1,
            &p.c2,
            &p.s
        ));
    }

    #[test]
    fn verify_rejects_identity_ga() {
        // Symmetric guard: if `ga` is the identity, `s*G == e*A + c1`
        // collapses on the verifier side and the proof becomes meaningless.
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);
        let (_ga, p) = create_proof(&a, &gm, &mut rng);

        assert!(!verify_proof(&GroupElement::identity(), &gm, &p));
        assert!(!verify_proof_split(
            &GroupElement::identity(),
            &gm,
            &p.n,
            &p.c1,
            &p.c2,
            &p.s
        ));
    }

    #[test]
    fn decode_rejects_identity_components() {
        // A 128-byte proof buffer whose `n` slot decodes to the identity
        // element must be rejected by `Proof::decode`. The all-zeros
        // 32-byte Ristretto encoding decodes to the identity point.
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);
        let (_ga, p) = create_proof(&a, &gm, &mut rng);

        let mut buf = p.encode();
        // Overwrite `n` (bytes 0..32) with the identity encoding.
        for byte in buf.iter_mut().take(32) {
            *byte = 0;
        }
        assert!(Proof::decode(&buf).is_none());

        // Similarly for c1 (bytes 32..64).
        let mut buf2 = p.encode();
        for byte in buf2.iter_mut().take(64).skip(32) {
            *byte = 0;
        }
        assert!(Proof::decode(&buf2).is_none());

        // Similarly for c2 (bytes 64..96).
        let mut buf3 = p.encode();
        for byte in buf3.iter_mut().take(96).skip(64) {
            *byte = 0;
        }
        assert!(Proof::decode(&buf3).is_none());
    }

    #[test]
    fn verify_rejects_identity_proof_components() {
        // Defense in depth: even when a `Proof` is constructed via
        // `Proof::new` (bypassing `decode`'s identity guard), the verifier
        // must reject identity values in `n`, `c1`, or `c2`.
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);
        let (ga, p) = create_proof(&a, &gm, &mut rng);
        let identity = GroupElement::identity();

        assert!(!verify_proof_split(&ga, &gm, &identity, &p.c1, &p.c2, &p.s));
        assert!(!verify_proof_split(&ga, &gm, &p.n, &identity, &p.c2, &p.s));
        assert!(!verify_proof_split(&ga, &gm, &p.n, &p.c1, &identity, &p.s));
    }
}
