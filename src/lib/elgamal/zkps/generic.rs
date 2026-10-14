//! Schnorr proofs of a discrete logarithm, generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::hashing::hash_to_nonzero_scalar;
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
/// The proof is non-interactive by the Fiat–Shamir transform: the challenge `e` is the hash of
/// `(A, M, N, c1, c2)`. It dereferences to its result `N`.
///
/// # Serialization
///
/// The encoding is `N || c1 || c2 || s`, the serialized elements and scalar; with serde it is a
/// base64 string of that.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Deref)]
pub struct Proof<G: Group> {
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

/// The Fiat–Shamir challenge `e = H(A, M, N, c1, c2)`.
fn challenge<G: Group>(
    ga: &G::Element,
    gm: &G::Element,
    gn: &G::Element,
    gc1: &G::Element,
    gc2: &G::Element,
) -> G::Scalar {
    hash_to_nonzero_scalar::<G>(&[
        G::serialize_element(ga).as_ref(),
        G::serialize_element(gm).as_ref(),
        G::serialize_element(gn).as_ref(),
        G::serialize_element(gc1).as_ref(),
        G::serialize_element(gc2).as_ref(),
    ])
}

/// One proof that `N = a * M` for the public key `ga = a * G`, with a fresh nonce from `rng`.
fn prove<G: Group, R: Rng + CryptoRng>(
    a: &G::Scalar,
    ga: &G::Element,
    gm: &G::Element,
    rng: &mut R,
) -> Proof<G> {
    let r = G::random_scalar(rng);
    let gn = *a * *gm;
    let gc1 = G::scalar_mult_gen(&r);
    let gc2 = r * *gm;
    let e = challenge::<G>(ga, gm, &gn, &gc1, &gc2);
    let s = G::ScalarCanBeZero::from(*a * e) + G::ScalarCanBeZero::from(r);
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
pub fn create_proof<G: Group, R: Rng + CryptoRng>(
    a: &G::Scalar,
    gm: &G::Element,
    rng: &mut R,
) -> (G::Element, Proof<G>) {
    let ga = G::scalar_mult_gen(a);
    let proof = prove::<G, R>(a, &ga, gm, rng);
    (ga, proof)
}

/// Two proofs of the same scalar `a` on the messages `gm1` and `gm2`, sharing the public key
/// `A = a * G`.
///
/// Each proof uses an independent nonce: reusing one across two proofs of the same witness on
/// different messages would let any verifier solve `a = (s1 - s2) / (e1 - e2)`.
pub fn create_proofs_same_scalar<G: Group, R: Rng + CryptoRng>(
    a: &G::Scalar,
    gm1: &G::Element,
    gm2: &G::Element,
    rng: &mut R,
) -> (G::Element, Proof<G>, Proof<G>) {
    let ga = G::scalar_mult_gen(a);
    let proof1 = prove::<G, R>(a, &ga, gm1, rng);
    let proof2 = prove::<G, R>(a, &ga, gm2, rng);
    (ga, proof1, proof2)
}

/// Verify a proof given as its components; see [`verify_proof`].
///
/// Checks `s * G == e * A + c1` and `s * M == e * N + c2` for the challenge `e`, and rejects an
/// identity element in any component, with which the equations would be vacuous.
#[must_use]
pub(crate) fn verify_proof_split<G: Group>(
    ga: &G::Element,
    gm: &G::Element,
    gn: &G::Element,
    gc1: &G::Element,
    gc2: &G::Element,
    s: &G::ScalarCanBeZero,
) -> bool {
    let identity = G::identity();
    if [ga, gm, gn, gc1, gc2].contains(&&identity) {
        return false;
    }
    let e = challenge::<G>(ga, gm, gn, gc1, gc2);
    // Both checks are linear combinations of points, so they could be evaluated as multiscalar
    // multiplications, which would roughly halve the cost of verification; the measured cost is
    // therefore conservative.
    *s * G::generator() == e * *ga + *gc1 && *s * *gm == e * *gn + *gc2
}

/// Verify that `p` proves `N = a * M` for the public key `ga = a * G` and the message `gm`.
#[must_use]
pub fn verify_proof<G: Group>(ga: &G::Element, gm: &G::Element, p: &Proof<G>) -> bool {
    verify_proof_split::<G>(ga, gm, &p.n, &p.c1, &p.c2, &p.s)
}
