//! Verifiable RSK and verifiable RSK-2.
//!
//! Implements the constructions exactly as specified in the paper:
//!
//! ```text
//!  VRSK(⟨B, C, Y⟩, s, k)
//!     = ⟨ T,
//!         ZKP{S = k * T},
//!         ZKP{B' = (s·k⁻¹) * B},
//!         ZKP{C' = s * C},
//!         ZKP{Y' = k * Y} ⟩
//!     where T = (s·k⁻¹)·G.
//!
//!  VRSK2(⟨B, C, Y⟩, s_from, s_to, k_from, k_to)
//!     = ⟨ S, K,
//!         ZKP{S_to = s_from * S},
//!         ZKP{K_to = k_from * K},
//!         VRSK(⟨B, C, Y⟩, s, k) where s = s_from⁻¹·s_to, k = k_from⁻¹·k_to ⟩
//! ```
//!
//! `VerifiableRSK2` mirrors the batched VRSK-2 layout: the per-factor
//! sub-proofs (`gs`, `gk`, `p_gs_to`, `p_gk_to`) tying the combined
//! commitments `S`, `K` to the published `S_from / S_to / K_from / K_to`
//! commitments, followed by the combined-scalar VRSK header (`gt`, `p_gs`)
//! and a per-message [`VerifiableRSKInner`] body. The per-factor and header
//! components depend only on the factor tuple and not on any individual
//! ciphertext.
//!
//! All ZKPs are forward (`ZKP{N = a * M}` has first component `N = a·M`).

use super::commitments::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
};
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSK {
    /// `T = (s·k⁻¹)·G`.
    pub(crate) gt: GroupElement,
    /// `ZKP{S = k * T}`: first component is `S = s·G`.
    pub(crate) p_gs: Proof,
    /// Per-message body.
    pub(crate) inner: VerifiableRSKInner,
}

impl VerifiableRSK {
    /// `T = (s·k⁻¹)·G`.
    pub fn gt(&self) -> &GroupElement {
        &self.gt
    }
    /// The proof `ZKP{S = k * T}`.
    pub fn p_gs(&self) -> &Proof {
        &self.p_gs
    }
    /// The per-message inner sub-proofs body.
    pub fn inner(&self) -> &VerifiableRSKInner {
        &self.inner
    }
}

impl VerifiableRSK {
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        s: &ScalarNonZero,
        k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let s_k_inv = s * k.invert();
        let gt = s_k_inv * G;
        let (_gk, p_gs) = create_proof(k, &gt, rng);
        let inner = VerifiableRSKInner::new(
            v,
            &s_k_inv,
            s,
            #[cfg(feature = "elgamal3")]
            k,
            rng,
        );
        Self { gt, p_gs, inner }
    }

    /// Reconstruct the RSK'd ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only — public callers should
    /// use [`verified_reconstruct`](Self::verified_reconstruct).
    pub(crate) fn result(&self) -> ElGamal {
        self.inner.result()
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        reshuffle_commitments: &PseudonymizationFactorCommitment,
        rekey_commitments: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, reshuffle_commitments, rekey_commitments) {
            Some(self.result())
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.result()
    }

    #[must_use]
    pub fn verify(
        &self,
        original: &ElGamal,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        let gs = reshuffle_commitment.0 .0;
        let gk = rekey_commitment.0 .0;
        if *self.p_gs != gs {
            return false;
        }
        if !verify_proof(&gk, &self.gt, &self.p_gs) {
            return false;
        }
        self.inner
            .verify(original, &self.gt, reshuffle_commitment, rekey_commitment)
    }
}

/// The per-message body of a VRSK proof once the `(gt, p_gs)` header has
/// been hoisted out — used by both [`VerifiableRSK2`] (per-message) and
/// the batched VRSK, which share this body type.
///
/// Carries only the genuinely per-ciphertext sub-proofs. Cannot stand
/// alone — it must be verified against an external `gt` plus the published
/// `(S, K)` commitments.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSKInner {
    /// `ZKP{B' = (s·k⁻¹) * B}`: first component is `B' = (s·k⁻¹)·B`.
    pub(crate) p_gb_prime: Proof,
    /// `ZKP{C' = s * C}`: first component is `C' = s·C`.
    pub(crate) p_gc_prime: Proof,
    /// `ZKP{Y' = k * Y}`: first component is `Y' = k·Y`.
    #[cfg(feature = "elgamal3")]
    pub(crate) p_gy_prime: Proof,
}

impl VerifiableRSKInner {
    /// The proof `ZKP{B' = (s·k⁻¹) * B}`.
    pub fn p_gb_prime(&self) -> &Proof {
        &self.p_gb_prime
    }
    /// The proof `ZKP{C' = s * C}`.
    pub fn p_gc_prime(&self) -> &Proof {
        &self.p_gc_prime
    }
    /// The proof `ZKP{Y' = k * Y}` (elgamal3 only).
    #[cfg(feature = "elgamal3")]
    pub fn p_gy_prime(&self) -> &Proof {
        &self.p_gy_prime
    }
}

impl VerifiableRSKInner {
    pub(super) fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        s_k_inv: &ScalarNonZero,
        s: &ScalarNonZero,
        #[cfg(feature = "elgamal3")] k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let (_t_again, p_gb_prime) = create_proof(s_k_inv, &v.gb, rng);
        let (_gs, p_gc_prime) = create_proof(s, &v.gc, rng);
        #[cfg(feature = "elgamal3")]
        let (_gk_again, p_gy_prime) = create_proof(k, &v.gy, rng);
        Self {
            p_gb_prime,
            p_gc_prime,
            #[cfg(feature = "elgamal3")]
            p_gy_prime,
        }
    }

    /// Reconstruct the RSK'd ciphertext, **without verifying** the proof.
    /// Internal use only.
    pub(crate) fn result(&self) -> ElGamal {
        ElGamal {
            gb: *self.p_gb_prime,
            gc: *self.p_gc_prime,
            #[cfg(feature = "elgamal3")]
            gy: *self.p_gy_prime,
        }
    }

    /// Verify this inner against an external `gt` and the published
    /// `(S, K)` commitments.
    #[must_use]
    pub fn verify(
        &self,
        original: &ElGamal,
        gt: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        #[cfg_attr(not(feature = "elgamal3"), allow(unused_variables))]
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        let gs = reshuffle_commitment.0 .0;
        if !verify_proof(gt, &original.gb, &self.p_gb_prime) {
            return false;
        }
        if !verify_proof(&gs, &original.gc, &self.p_gc_prime) {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if !verify_proof(&rekey_commitment.0 .0, &original.gy, &self.p_gy_prime) {
            return false;
        }
        true
    }

    /// Verify this inner and return the reconstructed RSK'd ciphertext.
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        gt: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, gt, reshuffle_commitment, rekey_commitment) {
            Some(self.result())
        } else {
            None
        }
    }
}

/// Verifiable RSK-2: per-factor sub-proofs (`p_gs_to`, `p_gk_to`) tying the
/// combined commitments `S`, `K` to the published `S_from`, `S_to`,
/// `K_from`, `K_to` commitments, plus a [`VerifiableRSK`] over the combined
/// scalars `(s, k) = (s_from⁻¹·s_to, k_from⁻¹·k_to)`.
///
/// Mirrors the batched VRSK-2 layout: factor block + inner VRSK (batched or
/// per-message).
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSK2 {
    /// `S = (s_from⁻¹·s_to)·G`.
    pub(crate) gs: GroupElement,
    /// `K = (k_from⁻¹·k_to)·G`.
    pub(crate) gk: GroupElement,
    /// `ZKP{S_to = s_from * S}`: first component is `S_to = s_to·G`.
    pub(crate) p_gs_to: Proof,
    /// `ZKP{K_to = k_from * K}`: first component is `K_to = k_to·G`.
    pub(crate) p_gk_to: Proof,
    /// VRSK over the combined scalars.
    pub(crate) inner: VerifiableRSK,
}

impl VerifiableRSK2 {
    /// The combined reshuffle commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn gs(&self) -> &GroupElement {
        &self.gs
    }
    /// The combined rekey commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn gk(&self) -> &GroupElement {
        &self.gk
    }
    /// The per-factor sub-proof `ZKP{S_to = s_from * S}`.
    pub fn p_gs_to(&self) -> &Proof {
        &self.p_gs_to
    }
    /// The per-factor sub-proof `ZKP{K_to = k_from * K}`.
    pub fn p_gk_to(&self) -> &Proof {
        &self.p_gk_to
    }
    /// The inner VRSK over the combined scalars.
    pub fn inner(&self) -> &VerifiableRSK {
        &self.inner
    }
}

impl VerifiableRSK2 {
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let s = s_from.invert() * s_to;
        let k = k_from.invert() * k_to;
        let gs = s * G;
        let gk = k * G;
        let (_gs_from, p_gs_to) = create_proof(s_from, &gs, rng);
        let (_gk_from, p_gk_to) = create_proof(k_from, &gk, rng);
        let inner = VerifiableRSK::new(v, &s, &k, rng);
        Self {
            gs,
            gk,
            p_gs_to,
            p_gk_to,
            inner,
        }
    }

    /// Reconstruct the RSK'd ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only.
    pub(crate) fn result(&self) -> ElGamal {
        self.inner.result()
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(
            original,
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) {
            Some(self.result())
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.result()
    }

    /// Verify the per-factor sub-proofs (`p_gs_to`, `p_gk_to`) tying the
    /// combined commitments to the published factor commitments. Does not
    /// verify the inner VRSK's per-message body — use [`Self::verify`] or
    /// [`Self::verified_reconstruct`] for that.
    #[must_use]
    pub fn verify_factor(
        &self,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        let gs_from = s_from_commitments.0 .0;
        let gs_to = s_to_commitments.0 .0;
        let gk_from = k_from_commitments.0 .0;
        let gk_to = k_to_commitments.0 .0;
        *self.p_gs_to == gs_to
            && verify_proof(&gs_from, &self.gs, &self.p_gs_to)
            && *self.p_gk_to == gk_to
            && verify_proof(&gk_from, &self.gk, &self.p_gk_to)
    }

    /// The combined reshuffle commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn combined_reshuffle_commitment(&self) -> PseudonymizationFactorCommitment {
        PseudonymizationFactorCommitment(FactorCommitment(self.gs))
    }

    /// The combined rekey commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn combined_rekey_commitment(&self) -> RekeyFactorCommitment {
        RekeyFactorCommitment(FactorCommitment(self.gk))
    }

    #[must_use]
    pub fn verify(
        &self,
        original: &ElGamal,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        self.verify_factor(
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) && self.inner.verify(
            original,
            &self.combined_reshuffle_commitment(),
            &self.combined_rekey_commitment(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::G;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::{rsk, rsk2};

    fn setup_ct() -> ElGamal {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        encrypt(&m, &pk, &mut rng)
    }

    #[test]
    fn vrsk_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK::new(&c, &s, &k, &mut rng);
        let expected = rsk(&c, &s, &k);
        let s_com = PseudonymizationFactorCommitment::new(&s);
        let k_com = RekeyFactorCommitment::new(&k);
        assert!(proof.verify(&c, &s_com, &k_com));
        assert_eq!(
            proof.verified_reconstruct(&c, &s_com, &k_com),
            Some(expected)
        );
    }

    #[test]
    fn vrsk_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRSK::new(&c, &s, &k, &mut rng);
        let s_com = PseudonymizationFactorCommitment::new(&s);
        let k_com = RekeyFactorCommitment::new(&k);
        proof.inner.p_gb_prime.c1 = proof.inner.p_gb_prime.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify(&c, &s_com, &k_com));
    }

    #[test]
    fn vrsk_wrong_s_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK::new(&c, &s, &k, &mut rng);
        let wrong_s = PseudonymizationFactorCommitment::new(&ScalarNonZero::random(&mut rng));
        let k_com = RekeyFactorCommitment::new(&k);
        assert!(!proof.verify(&c, &wrong_s, &k_com));
    }

    #[test]
    fn vrsk2_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK2::new(&c, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let expected = rsk2(&c, &s_from, &s_to, &k_from, &k_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(proof.verify(&c, &s_from_com, &s_to_com, &k_from_com, &k_to_com));
        assert_eq!(
            proof.verified_reconstruct(&c, &s_from_com, &s_to_com, &k_from_com, &k_to_com),
            Some(expected)
        );
    }

    #[test]
    fn vrsk2_wrong_to_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK2::new(&c, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_other = RekeyFactorCommitment::new(&ScalarNonZero::random(&mut rng));
        assert!(!proof.verify(&c, &s_from_com, &s_to_com, &k_from_com, &k_to_other));
    }

    #[test]
    fn vrsk2_factor_then_many_inner() {
        let mut rng = rand::rng();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let c1 = setup_ct();
        let c2 = setup_ct();
        let vrsk2 = VerifiableRSK2::new(&c1, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(vrsk2.verify_factor(&s_from_com, &s_to_com, &k_from_com, &k_to_com));
        let s = s_from.invert() * s_to;
        let k = k_from.invert() * k_to;
        let inner2 = VerifiableRSK::new(&c2, &s, &k, &mut rng);
        assert!(inner2.verify(
            &c2,
            &vrsk2.combined_reshuffle_commitment(),
            &vrsk2.combined_rekey_commitment(),
        ));
    }
}
