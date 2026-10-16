//! Schnorr zero-knowledge proofs of a discrete logarithm, non-interactive by the Fiat–Shamir
//! transform.
//!
//! - [`Proof`]: a proof that `N = a * M` for a secret scalar `a`, which reveals `N` but not `a`
//! - [`create_proof`]/[`verify_proof`]: create and verify proofs
//! - [`create_proofs_same_scalar`]: two proofs of the same scalar on two bases, for the
//!   verifiable reshuffle
//!
//! The proofs are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances. The proof encoding is the
//! four-element one of the published paper (Definition 8); the challenge hash is domain
//! separated by the ciphersuite's context string under the label `"ZKPChallenge-"`.
//! [`dleq`](crate::elgamal::dleq) has the two-scalar encoding of RFC 9497, for interoperability
//! with the two-party protocol; the verifiable operations use the encoding of this module.
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
//! # use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
//! # use libpep::elgamal::arithmetic::scalars::ScalarNonZero;
//! # use libpep::elgamal::zkps::{create_proof, verify_proof};
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

pub mod generic;

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use crate::elgamal::arithmetic::Ristretto255;
use rand_core::{CryptoRng, Rng};

/// The [`Proof`](generic::Proof) over ristretto255.
pub type Proof = generic::Proof<Ristretto255>;

/// Prove that `N = a * M` for the secret scalar `a` and the message `M = gm`; see
/// [`generic::create_proof`].
pub fn create_proof<R: Rng + CryptoRng>(
    a: &ScalarNonZero,
    gm: &GroupElement,
    rng: &mut R,
) -> (GroupElement, Proof) {
    generic::create_proof::<Ristretto255, R>(a, gm, rng)
}

/// Two proofs of the same scalar on two messages; see [`generic::create_proofs_same_scalar`].
pub fn create_proofs_same_scalar<R: Rng + CryptoRng>(
    a: &ScalarNonZero,
    gm1: &GroupElement,
    gm2: &GroupElement,
    rng: &mut R,
) -> (GroupElement, Proof, Proof) {
    generic::create_proofs_same_scalar::<Ristretto255, R>(a, gm1, gm2, rng)
}

/// Verify a proof; see [`generic::verify_proof`].
#[must_use]
pub fn verify_proof(ga: &GroupElement, gm: &GroupElement, p: &Proof) -> bool {
    generic::verify_proof::<Ristretto255>(ga, gm, p)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::elgamal::arithmetic::group_elements::GroupElement;
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::arithmetic::Ristretto255;
    use crate::elgamal::zkps::generic::verify_proof_split;
    use crate::elgamal::zkps::{create_proof, create_proofs_same_scalar, verify_proof, Proof};

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
        assert!(!verify_proof_split::<Ristretto255>(
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
        assert!(!verify_proof_split::<Ristretto255>(
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

        assert!(!verify_proof_split::<Ristretto255>(
            &ga, &gm, &identity, &p.c1, &p.c2, &p.s
        ));
        assert!(!verify_proof_split::<Ristretto255>(
            &ga, &gm, &p.n, &identity, &p.c2, &p.s
        ));
        assert!(!verify_proof_split::<Ristretto255>(
            &ga, &gm, &p.n, &p.c1, &identity, &p.s
        ));
    }
}
