//! Schnorr zero-knowledge proofs of a discrete logarithm, non-interactive by the Fiat-Shamir
//! transform.
//!
//! - [`Proof`]: a proof that `N = a * M` for a secret scalar `a`, which reveals `N` but not `a`
//! - [`create_proof`]/[`verify_proof`]: create and verify proofs
//! - [`create_proofs_same_scalar`]: two proofs of the same scalar on two bases, for the
//!   verifiable reshuffle
//!
//! The proofs are stored over a [`Group`] and created and verified under a [`Ciphersuite`]. The proof encoding
//! is the four-element one, `(N, C1, C2, s)`, of a Chaum-Pedersen proof of equality of discrete
//! logarithms (a DLEQ proof) made non-interactive with Fiat-Shamir; the challenge hash is domain
//! separated by the ciphersuite's context string under the label `"ZKPChallenge-"`.
//! [`dleq`](crate::elgamal::dleq) has the two-scalar encoding; the verifiable operations use the
//! encoding of this module.
//!
//! # Security properties
//!
//! - Zero-knowledge: the verifier learns nothing about the secret scalar beyond what the proof shows.
//! - Soundness: it is computationally infeasible to create a valid proof without knowing the secret.
//! - Non-interactive: prover and verifier do not interact, thanks to Fiat-Shamir.
//!
//! # Examples
//!
//! ```
//! # use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
//! # use libpep::elgamal::arithmetic::scalars::ScalarNonZero;
//! # use libpep::elgamal::arithmetic::Ristretto255Sha512;
//! # use libpep::elgamal::zkps::{create_proof, verify_proof};
//! # let mut rng = rand::rng();
//! let secret = ScalarNonZero::random(&mut rng);
//! let message = GroupElement::random(&mut rng);
//!
//! // Prover creates a proof
//! let (public_key, proof) = create_proof::<Ristretto255Sha512, _>(&secret, &message, &mut rng);
//!
//! // Verifier checks the proof
//! assert!(verify_proof::<Ristretto255Sha512>(&public_key, &message, &proof));
//! ```

use crate::elgamal::arithmetic::ciphersuite::{
    Ciphersuite, ElementOf, ScalarCanBeZeroOf, ScalarOf,
};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::Ristretto255;
use base64::engine::general_purpose;
use base64::Engine;
use derive_more::Deref;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::de::{Error, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use std::fmt::Formatter;

/// A zero-knowledge proof that `N = a * M` for a secret scalar `a`, verifiable against the
/// public key `A = a * G` and the message `M`.
///
/// The proof is non-interactive by the Fiat-Shamir transform: the challenge `e` is
/// `HashToScalar(A || M || N || c1 || c2)` of the ciphersuite under the domain separation tag
/// `"ZKPChallenge-" || contextString`, so that a proof of one deployment or proof type never
/// verifies as another. It dereferences to its result `N`.
///
/// # Serialization
///
/// The encoding is `N || c1 || c2 || s`, the serialized elements and scalar; with serde it is a
/// base64 string of that.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Deref)]
pub struct Proof<G: Group = Ristretto255> {
    /// The result `N = a * M`.
    #[deref]
    pub(crate) n: G::Element,
    /// The commitment `c1 = r * G` for the nonce `r`.
    pub(crate) c1: G::Element,
    /// The commitment `c2 = r * M`.
    pub(crate) c2: G::Element,
    /// The response `s = a * e + r`.
    pub(crate) s: G::ScalarCanBeZero,
}

impl<G: Group> Proof<G> {
    /// The length of a serialized proof in bytes: three elements and one scalar.
    pub const LENGTH: usize = 3 * G::NE + G::NS;

    /// The claimed result `N = a * M`.
    pub fn n(&self) -> &G::Element {
        &self.n
    }

    /// First commitment `c1 = r * G`.
    pub fn c1(&self) -> &G::Element {
        &self.c1
    }

    /// Second commitment `c2 = r * M`.
    pub fn c2(&self) -> &G::Element {
        &self.c2
    }

    /// Response scalar `s = a * e + r`.
    pub fn s(&self) -> &G::ScalarCanBeZero {
        &self.s
    }

    /// Encode as [`LENGTH`](Self::LENGTH) bytes: `N || c1 || c2 || s`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LENGTH);
        out.extend_from_slice(G::serialize_element(&self.n).as_ref());
        out.extend_from_slice(G::serialize_element(&self.c1).as_ref());
        out.extend_from_slice(G::serialize_element(&self.c2).as_ref());
        out.extend_from_slice(G::serialize_scalar_can_be_zero(&self.s).as_ref());
        out
    }

    /// Decode from exactly [`LENGTH`](Self::LENGTH) bytes.
    ///
    /// Returns `None` for any other length, for a component that is not a canonical encoding,
    /// and for an identity element in `N`, `c1` or `c2`, which would make the verification
    /// equations vacuous.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LENGTH {
            return None;
        }
        let ne = G::NE;
        Some(Self {
            n: G::deserialize_element(&bytes[..ne])?,
            c1: G::deserialize_element(&bytes[ne..2 * ne])?,
            c2: G::deserialize_element(&bytes[2 * ne..3 * ne])?,
            s: G::deserialize_scalar_can_be_zero(&bytes[3 * ne..])?,
        })
    }

    /// Encode as a URL-safe base64 string.
    pub fn to_base64(&self) -> String {
        general_purpose::URL_SAFE.encode(self.to_bytes())
    }

    /// Decode from a URL-safe base64 string.
    pub fn from_base64(s: &str) -> Option<Self> {
        general_purpose::URL_SAFE
            .decode(s)
            .ok()
            .and_then(|v| Self::from_slice(&v))
    }
}

#[cfg(feature = "serde")]
impl<G: Group> Serialize for Proof<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group> Deserialize<'de> for Proof<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProofVisitor<G>(std::marker::PhantomData<G>);
        impl<G: Group> Visitor<'_> for ProofVisitor<G> {
            type Value = Proof<G>;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 encoded string representing a Proof")
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                Proof::from_base64(v)
                    .ok_or_else(|| E::custom(format!("invalid base64 encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(ProofVisitor(std::marker::PhantomData))
    }
}

/// The Fiat-Shamir challenge `e = HashToScalar(A || M || N || c1 || c2)` under the DST
/// `"ZKPChallenge-" || contextString`. The elements have a fixed size, so the transcript needs no
/// length prefixes. A zero digest (negligible) is mapped to one.
fn challenge<C: Ciphersuite>(
    ga: &ElementOf<C>,
    gm: &ElementOf<C>,
    gn: &ElementOf<C>,
    gc1: &ElementOf<C>,
    gc2: &ElementOf<C>,
) -> ScalarOf<C> {
    let mut transcript = Vec::with_capacity(5 * C::Group::NE);
    for element in [ga, gm, gn, gc1, gc2] {
        transcript.extend_from_slice(C::Group::serialize_element(element).as_ref());
    }
    C::hash_to_scalar(&transcript, &C::ID.dst(b"ZKPChallenge-"))
        .unwrap_or_else(C::Group::scalar_one)
}

/// One proof that `N = a * M` for the public key `ga = a * G`, with a fresh nonce from `rng`.
fn prove<C: Ciphersuite, R: Rng + CryptoRng>(
    a: &ScalarOf<C>,
    ga: &ElementOf<C>,
    gm: &ElementOf<C>,
    rng: &mut R,
) -> Proof<C::Group> {
    let r = C::Group::random_scalar(rng);
    let gn = *a * *gm;
    let gc1 = C::Group::scalar_mult_gen(&r);
    let gc2 = r * *gm;
    let e = challenge::<C>(ga, gm, &gn, &gc1, &gc2);
    let s = ScalarCanBeZeroOf::<C>::from(*a * e) + ScalarCanBeZeroOf::<C>::from(r);
    Proof {
        n: gn,
        c1: gc1,
        c2: gc2,
        s,
    }
}

/// Prove that `N = a * M` for the secret scalar `a` and the message `M = gm`.
///
/// Returns the public key `A = a * G` and the proof, which carries `N`.
pub fn create_proof<C: Ciphersuite, R: Rng + CryptoRng>(
    a: &ScalarOf<C>,
    gm: &ElementOf<C>,
    rng: &mut R,
) -> (ElementOf<C>, Proof<C::Group>) {
    let ga = C::Group::scalar_mult_gen(a);
    let proof = prove::<C, R>(a, &ga, gm, rng);
    (ga, proof)
}

/// Two proofs of the same scalar `a` on the messages `gm1` and `gm2`, sharing the public key
/// `A = a * G`.
///
/// Each proof uses an independent nonce: reusing one across two proofs of the same witness on
/// different messages would let any verifier solve `a = (s1 - s2) / (e1 - e2)`.
pub fn create_proofs_same_scalar<C: Ciphersuite, R: Rng + CryptoRng>(
    a: &ScalarOf<C>,
    gm1: &ElementOf<C>,
    gm2: &ElementOf<C>,
    rng: &mut R,
) -> (ElementOf<C>, Proof<C::Group>, Proof<C::Group>) {
    let ga = C::Group::scalar_mult_gen(a);
    let proof1 = prove::<C, R>(a, &ga, gm1, rng);
    let proof2 = prove::<C, R>(a, &ga, gm2, rng);
    (ga, proof1, proof2)
}

/// Verify a proof given as its components; see [`verify_proof`].
///
/// Checks `s * G == e * A + c1` and `s * M == e * N + c2` for the challenge `e`, and rejects an
/// identity element in any component, with which the equations would be vacuous.
#[must_use]
pub(crate) fn verify_proof_split<C: Ciphersuite>(
    ga: &ElementOf<C>,
    gm: &ElementOf<C>,
    gn: &ElementOf<C>,
    gc1: &ElementOf<C>,
    gc2: &ElementOf<C>,
    s: &ScalarCanBeZeroOf<C>,
) -> bool {
    let identity = C::Group::identity();
    if [ga, gm, gn, gc1, gc2].contains(&&identity) {
        return false;
    }
    let e = challenge::<C>(ga, gm, gn, gc1, gc2);
    // Both checks are linear combinations of points, so they could be evaluated as multiscalar
    // multiplications, which would roughly halve the cost of verification. The measured cost is
    // therefore conservative.
    *s * C::Group::generator() == e * *ga + *gc1 && *s * *gm == e * *gn + *gc2
}

/// Verify that `p` proves `N = a * M` for the public key `ga = a * G` and the message `gm`.
#[must_use]
pub fn verify_proof<C: Ciphersuite>(
    ga: &ElementOf<C>,
    gm: &ElementOf<C>,
    p: &Proof<C::Group>,
) -> bool {
    verify_proof_split::<C>(ga, gm, &p.n, &p.c1, &p.c2, &p.s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::verify_proof_split;
    use crate::elgamal::arithmetic::group_elements::GroupElement;
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::arithmetic::Ristretto255;
    use crate::elgamal::arithmetic::Ristretto255Sha512;
    use rand_core::{CryptoRng, Rng};

    type C = Ristretto255Sha512;

    type Proof = super::Proof<Ristretto255>;

    fn create_proof<R: Rng + CryptoRng>(
        a: &ScalarNonZero,
        gm: &GroupElement,
        rng: &mut R,
    ) -> (GroupElement, Proof) {
        super::create_proof::<C, R>(a, gm, rng)
    }

    fn create_proofs_same_scalar<R: Rng + CryptoRng>(
        a: &ScalarNonZero,
        gm1: &GroupElement,
        gm2: &GroupElement,
        rng: &mut R,
    ) -> (GroupElement, Proof, Proof) {
        super::create_proofs_same_scalar::<C, R>(a, gm1, gm2, rng)
    }

    fn verify_proof(ga: &GroupElement, gm: &GroupElement, p: &Proof) -> bool {
        super::verify_proof::<C>(ga, gm, p)
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
        assert!(!verify_proof_split::<C>(
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
        assert!(!verify_proof_split::<C>(
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
        // A proof buffer with a component that decodes to the identity element must be
        // rejected. The all-zeros 32-byte Ristretto encoding decodes to the identity point.
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);
        let (_ga, p) = create_proof(&a, &gm, &mut rng);

        assert_eq!(Proof::from_slice(&p.to_bytes()), Some(p));
        for component in 0..3 {
            let mut buf = p.to_bytes();
            // Overwrite the component with the identity encoding.
            buf[component * 32..(component + 1) * 32].fill(0);
            assert!(Proof::from_slice(&buf).is_none());
        }
        assert!(Proof::from_slice(&p.to_bytes()[1..]).is_none());
    }

    #[test]
    fn verify_rejects_identity_proof_components() {
        // Defense in depth: even when a `Proof` is built by hand (bypassing the identity guard
        // of `from_slice`), the verifier must reject identity values in `n`, `c1`, or `c2`.
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let gm = GroupElement::random(&mut rng);
        let (ga, p) = create_proof(&a, &gm, &mut rng);
        let identity = GroupElement::identity();

        assert!(!verify_proof_split::<C>(
            &ga, &gm, &identity, &p.c1, &p.c2, &p.s
        ));
        assert!(!verify_proof_split::<C>(
            &ga, &gm, &p.n, &identity, &p.c2, &p.s
        ));
        assert!(!verify_proof_split::<C>(
            &ga, &gm, &p.n, &p.c1, &identity, &p.s
        ));
    }
}
