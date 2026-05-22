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

use super::commitments::PseudonymizationFactorCommitment;
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, create_proofs_same_scalar, verify_proof, Proof};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Verifiable reshuffle: `⟨ZKP{B' = s * B}, ZKP{C' = s * C}⟩`.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableReshuffle {
    /// `ZKP{B' = s * B}`: first component is `B' = s·B`.
    pub p_gb_prime: Proof,
    /// `ZKP{C' = s * C}`: first component is `C' = s·C`.
    pub p_gc_prime: Proof,
}

impl VerifiableReshuffle {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s: &ScalarNonZero, rng: &mut R) -> Self {
        let (_gs, p_gb_prime, p_gc_prime) = create_proofs_same_scalar(s, &v.gb, &v.gc, rng);
        Self {
            p_gb_prime,
            p_gc_prime,
        }
    }

    pub fn result(&self, _original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: *self.p_gb_prime,
            gc: *self.p_gc_prime,
            #[cfg(feature = "elgamal3")]
            gy: _original.gy,
        }
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        commitments: &PseudonymizationFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, commitments) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.result(original)
    }

    #[must_use]
    fn verify(&self, original: &ElGamal, commitment: &PseudonymizationFactorCommitment) -> bool {
        let gs = commitment.0 .0;
        verify_proof(&gs, &original.gb, &self.p_gb_prime)
            && verify_proof(&gs, &original.gc, &self.p_gc_prime)
    }

    #[must_use]
    pub fn verify_reshuffle(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        commitment: &PseudonymizationFactorCommitment,
    ) -> bool {
        if !self.verify(original, commitment) {
            return false;
        }
        if new.gb != *self.p_gb_prime || new.gc != *self.p_gc_prime {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if new.gy != original.gy {
            return false;
        }
        true
    }
}

/// Verifiable reshuffle-2: a [`VerifiableReshuffle`] over the combined scalar
/// `s = s_from⁻¹·s_to`, plus the per-factor sub-proof tying `S = s·G` to the
/// published `S_from`, `S_to` commitments.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableReshuffle2 {
    /// `S = (s_from⁻¹·s_to)·G`.
    pub gs: GroupElement,
    /// `ZKP{S_to = s_from * S}`: first component is `S_to = s_to·G`.
    pub p_gs_to: Proof,
    /// The per-message reshuffle under the combined scalar.
    pub inner: VerifiableReshuffle,
}

impl VerifiableReshuffle2 {
    pub fn new<R: RngCore + CryptoRng>(
        v: &ElGamal,
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let s = s_from.invert() * s_to;
        let gs = s * G;
        let (_gs_from, p_gs_to) = create_proof(s_from, &gs, rng);
        let inner = VerifiableReshuffle::new(v, &s, rng);
        Self { gs, p_gs_to, inner }
    }

    pub fn result(&self, original: &ElGamal) -> ElGamal {
        self.inner.result(original)
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        from_commitments: &PseudonymizationFactorCommitment,
        to_commitments: &PseudonymizationFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, from_commitments, to_commitments) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.result(original)
    }

    /// Verify the per-factor sub-proof (`p_gs_to`) once. The combined
    /// commitment `S = self.gs` can then be reused to verify many per-message
    /// inner proofs via [`VerifiableReshuffle::verify_reshuffle`] against the
    /// combined commitment from [`Self::combined_commitment`].
    #[must_use]
    pub fn verify_factor(
        &self,
        from_commitments: &PseudonymizationFactorCommitment,
        to_commitments: &PseudonymizationFactorCommitment,
    ) -> bool {
        let gs_from = from_commitments.0 .0;
        let gs_to = to_commitments.0 .0;
        *self.p_gs_to == gs_to && verify_proof(&gs_from, &self.gs, &self.p_gs_to)
    }

    /// The combined commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn combined_commitment(&self) -> PseudonymizationFactorCommitment {
        PseudonymizationFactorCommitment(super::commitments::FactorCommitment(self.gs))
    }

    #[must_use]
    fn verify(
        &self,
        original: &ElGamal,
        from_commitments: &PseudonymizationFactorCommitment,
        to_commitments: &PseudonymizationFactorCommitment,
    ) -> bool {
        self.verify_factor(from_commitments, to_commitments)
            && self.inner.verify(original, &self.combined_commitment())
    }

    #[must_use]
    pub fn verify_reshuffle2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        from_commitments: &PseudonymizationFactorCommitment,
        to_commitments: &PseudonymizationFactorCommitment,
    ) -> bool {
        self.verify_factor(from_commitments, to_commitments)
            && self
                .inner
                .verify_reshuffle(original, new, &self.combined_commitment())
    }
}

pub fn verifiable_reshuffle<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffle {
    VerifiableReshuffle::new(m, s, rng)
}

pub fn verifiable_reshuffle2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffle2 {
    VerifiableReshuffle2::new(m, s_from, s_to, rng)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::G;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::{reshuffle, reshuffle2};

    fn setup_ct() -> ElGamal {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        encrypt(&m, &pk, &mut rng)
    }

    fn tamper(c: &ElGamal) -> ElGamal {
        let mut rng = rand::rng();
        let mut t = *c;
        t.gb = t.gb + GroupElement::random(&mut rng);
        t
    }

    // ---- VRS ----

    #[test]
    fn vrs_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle::new(&c, &s, &mut rng);
        let result = reshuffle(&c, &s);
        let commitments = PseudonymizationFactorCommitment::new(&s);
        assert!(proof.verify_reshuffle(&c, &result, &commitments));
    }

    #[test]
    fn vrs_tampered_output_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle::new(&c, &s, &mut rng);
        let real = reshuffle(&c, &s);
        let bad = tamper(&real);
        let commitments = PseudonymizationFactorCommitment::new(&s);
        assert!(!proof.verify_reshuffle(&c, &bad, &commitments));
    }

    #[test]
    fn vrs_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableReshuffle::new(&c, &s, &mut rng);
        let result = reshuffle(&c, &s);
        let commitments = PseudonymizationFactorCommitment::new(&s);
        proof.p_gb_prime.c1 = proof.p_gb_prime.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify_reshuffle(&c, &result, &commitments));
    }

    #[test]
    fn vrs_wrong_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let s_other = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle::new(&c, &s, &mut rng);
        let result = reshuffle(&c, &s);
        let wrong = PseudonymizationFactorCommitment::new(&s_other);
        assert!(!proof.verify_reshuffle(&c, &result, &wrong));
    }

    // ---- VRS2 ----

    #[test]
    fn vrs2_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle2::new(&c, &s_from, &s_to, &mut rng);
        let result = reshuffle2(&c, &s_from, &s_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        assert!(proof.verify_reshuffle2(&c, &result, &s_from_com, &s_to_com));
    }

    #[test]
    fn vrs2_tampered_output_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle2::new(&c, &s_from, &s_to, &mut rng);
        let real = reshuffle2(&c, &s_from, &s_to);
        let bad = tamper(&real);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        assert!(!proof.verify_reshuffle2(&c, &bad, &s_from_com, &s_to_com));
    }

    #[test]
    fn vrs2_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableReshuffle2::new(&c, &s_from, &s_to, &mut rng);
        let result = reshuffle2(&c, &s_from, &s_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        proof.inner.p_gb_prime.c2 = proof.inner.p_gb_prime.c2 + GroupElement::random(&mut rng);
        assert!(!proof.verify_reshuffle2(&c, &result, &s_from_com, &s_to_com));
    }

    #[test]
    fn vrs2_wrong_to_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableReshuffle2::new(&c, &s_from, &s_to, &mut rng);
        let result = reshuffle2(&c, &s_from, &s_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_other = PseudonymizationFactorCommitment::new(&ScalarNonZero::random(&mut rng));
        assert!(!proof.verify_reshuffle2(&c, &result, &s_from_com, &s_to_other));
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
        let result2 = reshuffle2(&c2, &s_from, &s_to);
        assert!(inner2.verify_reshuffle(&c2, &result2, &vrs2.combined_commitment()));
    }
}
