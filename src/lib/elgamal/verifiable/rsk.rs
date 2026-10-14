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
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::zkps::generic::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
/// Proof of a verifiable RSK: the reshuffle and rekey of one ciphertext with a factor pair `(s,
/// k)`.
pub struct VerifiableRSK<G: Group> {
    /// `T = (s·k⁻¹)·G`.
    pub(crate) gt: G::Element,
    /// `ZKP{S = k * T}`: first component is `S = s·G`.
    pub(crate) p_gs: Proof<G>,
    /// Per-message body.
    pub(crate) inner: VerifiableRSKInner<G>,
}

impl<G: Group> VerifiableRSK<G> {
    /// `T = (s·k⁻¹)·G`.
    pub fn gt(&self) -> &G::Element {
        &self.gt
    }
    /// The proof `ZKP{S = k * T}`.
    pub fn p_gs(&self) -> &Proof<G> {
        &self.p_gs
    }
    /// The per-message inner sub-proofs body.
    pub fn inner(&self) -> &VerifiableRSKInner<G> {
        &self.inner
    }
}

impl<G: Group> VerifiableRSK<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal<G>,
        s: &G::Scalar,
        k: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let s_k_inv = *s * G::scalar_inverse(k);
        let gt = s_k_inv * G::generator();
        let (_gk, p_gs) = create_proof::<G, R>(k, &gt, rng);
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
    pub(crate) fn result(&self) -> ElGamal<G> {
        self.inner.result()
    }

    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal<G>,
        reshuffle_commitments: &PseudonymizationFactorCommitment<G>,
        rekey_commitments: &RekeyFactorCommitment<G>,
    ) -> Option<ElGamal<G>> {
        if self.verify(original, reshuffle_commitments, rekey_commitments) {
            Some(self.result())
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    /// The result of the operation, without verifying the proof.
    pub fn unverified_reconstruct(&self) -> ElGamal<G> {
        self.result()
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        original: &ElGamal<G>,
        reshuffle_commitment: &PseudonymizationFactorCommitment<G>,
        rekey_commitment: &RekeyFactorCommitment<G>,
    ) -> bool {
        let gs = reshuffle_commitment.point();
        let gk = rekey_commitment.point();
        if *self.p_gs != gs {
            return false;
        }
        if !verify_proof::<G>(&gk, &self.gt, &self.p_gs) {
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRSKInner<G: Group> {
    /// `ZKP{B' = (s·k⁻¹) * B}`: first component is `B' = (s·k⁻¹)·B`.
    pub(crate) p_gb_prime: Proof<G>,
    /// `ZKP{C' = s * C}`: first component is `C' = s·C`.
    pub(crate) p_gc_prime: Proof<G>,
    /// `ZKP{Y' = k * Y}`: first component is `Y' = k·Y`.
    #[cfg(feature = "elgamal3")]
    pub(crate) p_gy_prime: Proof<G>,
}

impl<G: Group> VerifiableRSKInner<G> {
    /// The proof `ZKP{B' = (s·k⁻¹) * B}`.
    pub fn p_gb_prime(&self) -> &Proof<G> {
        &self.p_gb_prime
    }
    /// The proof `ZKP{C' = s * C}`.
    pub fn p_gc_prime(&self) -> &Proof<G> {
        &self.p_gc_prime
    }
    /// The proof `ZKP{Y' = k * Y}` (elgamal3 only).
    #[cfg(feature = "elgamal3")]
    pub fn p_gy_prime(&self) -> &Proof<G> {
        &self.p_gy_prime
    }
}

impl<G: Group> VerifiableRSKInner<G> {
    pub(super) fn new<R: Rng + CryptoRng>(
        v: &ElGamal<G>,
        s_k_inv: &G::Scalar,
        s: &G::Scalar,
        #[cfg(feature = "elgamal3")] k: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let (_t_again, p_gb_prime) = create_proof::<G, R>(s_k_inv, &v.gb, rng);
        let (_gs, p_gc_prime) = create_proof::<G, R>(s, &v.gc, rng);
        #[cfg(feature = "elgamal3")]
        let (_gk_again, p_gy_prime) = create_proof::<G, R>(k, &v.gy, rng);
        Self {
            p_gb_prime,
            p_gc_prime,
            #[cfg(feature = "elgamal3")]
            p_gy_prime,
        }
    }

    /// Reconstruct the RSK'd ciphertext, **without verifying** the proof.
    /// Internal use only.
    pub(crate) fn result(&self) -> ElGamal<G> {
        ElGamal {
            gb: *self.p_gb_prime,
            gc: *self.p_gc_prime,
            #[cfg(feature = "elgamal3")]
            gy: *self.p_gy_prime,
        }
    }

    /// Verify this inner against an external `gt` and the published
    /// `(S, K)` commitments. Crate-private: a caller-chosen `gt` would let any `B' = t·B`
    /// verify, so the inner is only checked through the proof that carries its `gt`.
    #[must_use]
    pub(crate) fn verify(
        &self,
        original: &ElGamal<G>,
        gt: &G::Element,
        reshuffle_commitment: &PseudonymizationFactorCommitment<G>,
        #[cfg_attr(not(feature = "elgamal3"), allow(unused_variables))]
        rekey_commitment: &RekeyFactorCommitment<G>,
    ) -> bool {
        let gs = reshuffle_commitment.point();
        if !verify_proof::<G>(gt, &original.gb, &self.p_gb_prime) {
            return false;
        }
        if !verify_proof::<G>(&gs, &original.gc, &self.p_gc_prime) {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if !verify_proof::<G>(&rekey_commitment.point(), &original.gy, &self.p_gy_prime) {
            return false;
        }
        true
    }

    /// Verify this inner and return the reconstructed RSK'd ciphertext.
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal<G>,
        gt: &G::Element,
        reshuffle_commitment: &PseudonymizationFactorCommitment<G>,
        rekey_commitment: &RekeyFactorCommitment<G>,
    ) -> Option<ElGamal<G>> {
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRSK2<G: Group> {
    /// `S = (s_from⁻¹·s_to)·G`.
    pub(crate) gs: G::Element,
    /// `K = (k_from⁻¹·k_to)·G`.
    pub(crate) gk: G::Element,
    /// `ZKP{S_to = s_from * S}`: first component is `S_to = s_to·G`.
    pub(crate) p_gs_to: Proof<G>,
    /// `ZKP{K_to = k_from * K}`: first component is `K_to = k_to·G`.
    pub(crate) p_gk_to: Proof<G>,
    /// VRSK over the combined scalars.
    pub(crate) inner: VerifiableRSK<G>,
}

impl<G: Group> VerifiableRSK2<G> {
    /// The combined reshuffle commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn gs(&self) -> &G::Element {
        &self.gs
    }
    /// The combined rekey commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn gk(&self) -> &G::Element {
        &self.gk
    }
    /// The per-factor sub-proof `ZKP{S_to = s_from * S}`.
    pub fn p_gs_to(&self) -> &Proof<G> {
        &self.p_gs_to
    }
    /// The per-factor sub-proof `ZKP{K_to = k_from * K}`.
    pub fn p_gk_to(&self) -> &Proof<G> {
        &self.p_gk_to
    }
    /// The inner VRSK over the combined scalars.
    pub fn inner(&self) -> &VerifiableRSK<G> {
        &self.inner
    }
}

impl<G: Group> VerifiableRSK2<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal<G>,
        s_from: &G::Scalar,
        s_to: &G::Scalar,
        k_from: &G::Scalar,
        k_to: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let s = G::scalar_inverse(s_from) * *s_to;
        let k = G::scalar_inverse(k_from) * *k_to;
        let gs = s * G::generator();
        let gk = k * G::generator();
        let (_gs_from, p_gs_to) = create_proof::<G, R>(s_from, &gs, rng);
        let (_gk_from, p_gk_to) = create_proof::<G, R>(k_from, &gk, rng);
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
    pub(crate) fn result(&self) -> ElGamal<G> {
        self.inner.result()
    }

    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal<G>,
        s_from_commitments: &PseudonymizationFactorCommitment<G>,
        s_to_commitments: &PseudonymizationFactorCommitment<G>,
        k_from_commitments: &RekeyFactorCommitment<G>,
        k_to_commitments: &RekeyFactorCommitment<G>,
    ) -> Option<ElGamal<G>> {
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
    /// The result of the operation, without verifying the proof.
    pub fn unverified_reconstruct(&self) -> ElGamal<G> {
        self.result()
    }

    /// Verify the per-factor sub-proofs (`p_gs_to`, `p_gk_to`) tying the
    /// combined commitments to the published factor commitments. Does not
    /// verify the inner VRSK's per-message body — use [`Self::verify`] or
    /// [`Self::verified_reconstruct`] for that.
    #[must_use]
    pub fn verify_factor(
        &self,
        s_from_commitments: &PseudonymizationFactorCommitment<G>,
        s_to_commitments: &PseudonymizationFactorCommitment<G>,
        k_from_commitments: &RekeyFactorCommitment<G>,
        k_to_commitments: &RekeyFactorCommitment<G>,
    ) -> bool {
        let gs_from = s_from_commitments.point();
        let gs_to = s_to_commitments.point();
        let gk_from = k_from_commitments.point();
        let gk_to = k_to_commitments.point();
        *self.p_gs_to == gs_to
            && verify_proof::<G>(&gs_from, &self.gs, &self.p_gs_to)
            && *self.p_gk_to == gk_to
            && verify_proof::<G>(&gk_from, &self.gk, &self.p_gk_to)
    }

    /// The combined reshuffle commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn combined_reshuffle_commitment(&self) -> PseudonymizationFactorCommitment<G> {
        PseudonymizationFactorCommitment(FactorCommitment(self.gs))
    }

    /// The combined rekey commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn combined_rekey_commitment(&self) -> RekeyFactorCommitment<G> {
        RekeyFactorCommitment(FactorCommitment(self.gk))
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        original: &ElGamal<G>,
        s_from_commitments: &PseudonymizationFactorCommitment<G>,
        s_to_commitments: &PseudonymizationFactorCommitment<G>,
        k_from_commitments: &RekeyFactorCommitment<G>,
        k_to_commitments: &RekeyFactorCommitment<G>,
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
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::encrypt;
    use crate::elgamal::primitives::{rsk, rsk2};
    use crate::elgamal::verifiable::{
        PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRSK, VerifiableRSK2,
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
