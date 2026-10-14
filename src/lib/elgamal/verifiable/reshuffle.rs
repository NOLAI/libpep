//! Verifiable reshuffle and verifiable reshuffle-2.
//!
//! Implements the constructions exactly as specified in the paper:
//!
//! ```text
//!  VReshuffle(⟨B, C, Y⟩, s)
//!     = ⟨ ZKP{B' = s * B}, ZKP{C' = s * C} ⟩
//!  VReshuffle2(⟨B, C, Y⟩, s_from, s_to)
//!     = ⟨ S, ZKP{S_to = s_from * S}, VReshuffle(⟨B, C, Y⟩, s_from⁻¹·s_to) ⟩
//! ```
//!
//! `VerifiableReshuffle2` is structurally a `VerifiableReshuffle` (over the
//! combined scalar `s = s_from⁻¹·s_to`) plus the per-factor sub-proof tying
//! `S` to the published `S_from`, `S_to` commitments. The per-factor sub-proof
//! depends only on `(s_from, s_to)` and not on any individual ciphertext.
//!
//! All proofs are forward (`ZKP{N = a * M}` has first component `N = a·M` and
//! is verified against the forward commitment `A = a·G`).

use super::commitments::{FactorCommitment, PseudonymizationFactorCommitment};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::zkps::generic::{create_proof, create_proofs_same_scalar, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Verifiable reshuffle: `⟨ZKP{B' = s * B}, ZKP{C' = s * C}⟩`.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableReshuffle<G: Group> {
    /// `ZKP{B' = s * B}`: first component is `B' = s·B`.
    pub(crate) p_gb_prime: Proof<G>,
    /// `ZKP{C' = s * C}`: first component is `C' = s·C`.
    pub(crate) p_gc_prime: Proof<G>,
}

impl<G: Group> VerifiableReshuffle<G> {
    /// The proof `ZKP{B' = s * B}`.
    pub fn p_gb_prime(&self) -> &Proof<G> {
        &self.p_gb_prime
    }
    /// The proof `ZKP{C' = s * C}`.
    pub fn p_gc_prime(&self) -> &Proof<G> {
        &self.p_gc_prime
    }
}

impl<G: Group> VerifiableReshuffle<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(v: &ElGamal<G>, s: &G::Scalar, rng: &mut R) -> Self {
        let (_gs, p_gb_prime, p_gc_prime) = create_proofs_same_scalar::<G, R>(s, &v.gb, &v.gc, rng);
        Self {
            p_gb_prime,
            p_gc_prime,
        }
    }

    /// Reconstruct the reshuffled ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only.
    pub(crate) fn result(&self, _original: &ElGamal<G>) -> ElGamal<G> {
        ElGamal {
            gb: *self.p_gb_prime,
            gc: *self.p_gc_prime,
            #[cfg(feature = "elgamal3")]
            gy: _original.gy,
        }
    }

    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal<G>,
        commitments: &PseudonymizationFactorCommitment<G>,
    ) -> Option<ElGamal<G>> {
        if self.verify(original, commitments) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    /// The result of the operation, without verifying the proof.
    pub fn unverified_reconstruct(&self, original: &ElGamal<G>) -> ElGamal<G> {
        self.result(original)
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        original: &ElGamal<G>,
        commitment: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        let gs = commitment.point();
        verify_proof::<G>(&gs, &original.gb, &self.p_gb_prime)
            && verify_proof::<G>(&gs, &original.gc, &self.p_gc_prime)
    }
}

/// Verifiable reshuffle-2: a [`VerifiableReshuffle`] over the combined scalar
/// `s = s_from⁻¹·s_to`, plus the per-factor sub-proof tying `S = s·G` to the
/// published `S_from`, `S_to` commitments.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableReshuffle2<G: Group> {
    /// `S = (s_from⁻¹·s_to)·G`.
    pub(crate) gs: G::Element,
    /// `ZKP{S_to = s_from * S}`: first component is `S_to = s_to·G`.
    pub(crate) p_gs_to: Proof<G>,
    /// The per-message reshuffle under the combined scalar.
    pub(crate) inner: VerifiableReshuffle<G>,
}

impl<G: Group> VerifiableReshuffle2<G> {
    /// The combined commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn gs(&self) -> &G::Element {
        &self.gs
    }
    /// The per-factor sub-proof `ZKP{S_to = s_from * S}`.
    pub fn p_gs_to(&self) -> &Proof<G> {
        &self.p_gs_to
    }
    /// The inner per-message reshuffle proof under the combined scalar.
    pub fn inner(&self) -> &VerifiableReshuffle<G> {
        &self.inner
    }
}

impl<G: Group> VerifiableReshuffle2<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal<G>,
        s_from: &G::Scalar,
        s_to: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let s = G::scalar_inverse(s_from) * *s_to;
        let gs = s * G::generator();
        let (_gs_from, p_gs_to) = create_proof::<G, R>(s_from, &gs, rng);
        let inner = VerifiableReshuffle::new(v, &s, rng);
        Self { gs, p_gs_to, inner }
    }

    /// Reconstruct the reshuffled ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only.
    pub(crate) fn result(&self, original: &ElGamal<G>) -> ElGamal<G> {
        self.inner.result(original)
    }

    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal<G>,
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> Option<ElGamal<G>> {
        if self.verify(original, from_commitments, to_commitments) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    /// The result of the operation, without verifying the proof.
    pub fn unverified_reconstruct(&self, original: &ElGamal<G>) -> ElGamal<G> {
        self.result(original)
    }

    /// Verify the per-factor sub-proof (`p_gs_to`) once. The combined
    /// commitment `S = self.gs` can then be reused to verify many per-message
    /// inner proofs via [`VerifiableReshuffle::verify`] against the
    /// combined commitment from [`Self::combined_commitment`].
    #[must_use]
    pub fn verify_factor(
        &self,
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        let gs_from = from_commitments.point();
        let gs_to = to_commitments.point();
        *self.p_gs_to == gs_to && verify_proof::<G>(&gs_from, &self.gs, &self.p_gs_to)
    }

    /// The combined commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn combined_commitment(&self) -> PseudonymizationFactorCommitment<G> {
        PseudonymizationFactorCommitment(FactorCommitment(self.gs))
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        original: &ElGamal<G>,
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        self.verify_factor(from_commitments, to_commitments)
            && self.inner.verify(original, &self.combined_commitment())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::encrypt;
    use crate::elgamal::primitives::{reshuffle, reshuffle2};
    use crate::elgamal::verifiable::{
        PseudonymizationFactorCommitment, VerifiableReshuffle, VerifiableReshuffle2,
    };
    use crate::elgamal::ElGamal;

    fn setup_ct() -> ElGamal {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        encrypt(&m, &pk, &mut rng)
    }

    #[test]
    fn vrs_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle::new(&c, &s, &mut rng);
        let expected = reshuffle(&c, &s);
        let commitments = PseudonymizationFactorCommitment::new(&s);
        assert!(proof.verify(&c, &commitments));
        assert_eq!(proof.verified_reconstruct(&c, &commitments), Some(expected));
    }

    #[test]
    fn vrs_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableReshuffle::new(&c, &s, &mut rng);
        let commitments = PseudonymizationFactorCommitment::new(&s);
        proof.p_gb_prime.c1 = proof.p_gb_prime.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify(&c, &commitments));
    }

    #[test]
    fn vrs_wrong_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let s_other = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle::new(&c, &s, &mut rng);
        let wrong = PseudonymizationFactorCommitment::new(&s_other);
        assert!(!proof.verify(&c, &wrong));
    }

    #[test]
    fn vrs2_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle2::new(&c, &s_from, &s_to, &mut rng);
        let expected = reshuffle2(&c, &s_from, &s_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        assert!(proof.verify(&c, &s_from_com, &s_to_com));
        assert_eq!(
            proof.verified_reconstruct(&c, &s_from_com, &s_to_com),
            Some(expected)
        );
    }

    #[test]
    fn vrs2_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableReshuffle2::new(&c, &s_from, &s_to, &mut rng);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        proof.inner.p_gb_prime.c2 = proof.inner.p_gb_prime.c2 + GroupElement::random(&mut rng);
        assert!(!proof.verify(&c, &s_from_com, &s_to_com));
    }

    #[test]
    fn vrs2_wrong_to_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle2::new(&c, &s_from, &s_to, &mut rng);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_other = PseudonymizationFactorCommitment::new(&ScalarNonZero::random(&mut rng));
        assert!(!proof.verify(&c, &s_from_com, &s_to_other));
    }

    #[test]
    fn vrs2_factor_then_many_inner() {
        let mut rng = rand::rng();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let c1 = setup_ct();
        let c2 = setup_ct();
        let vrs2 = VerifiableReshuffle2::new(&c1, &s_from, &s_to, &mut rng);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        assert!(vrs2.verify_factor(&s_from_com, &s_to_com));
        let s = s_from.invert() * s_to;
        let inner2 = VerifiableReshuffle::new(&c2, &s, &mut rng);
        assert!(inner2.verify(&c2, &vrs2.combined_commitment()));
    }
}
