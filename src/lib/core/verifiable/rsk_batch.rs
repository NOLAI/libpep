//! Batched verifiable RSK and RSK-2.

use super::commitments::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
};
use super::rsk::VerifiableRSKInner;
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub fn verifiable_rsk_batch<R: Rng + CryptoRng>(
    ciphertexts: &[ElGamal],
    s: &ScalarNonZero,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRSKBatch {
    VerifiableRSKBatch::new(ciphertexts, s, k, rng)
}

pub fn verifiable_rsk2_batch<R: Rng + CryptoRng>(
    ciphertexts: &[ElGamal],
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRSK2Batch {
    VerifiableRSK2Batch::new(ciphertexts, s_from, s_to, k_from, k_to, rng)
}

/// A batch of [`VerifiableRSK`] proofs sharing one `(s, k)` factor pair.
///
/// `gt = (s·k⁻¹)·G` and the `ZKP{S = k·T}` ([`Self::p_gs`]) depend only on
/// `(s, k)` and not on any individual ciphertext, so they are hoisted into
/// the batch header. Each per-message [`VerifiableRSKInner`] carries only
/// the genuinely ciphertext-dependent sub-proofs.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSKBatch {
    /// `T = (s·k⁻¹)·G`.
    pub gt: GroupElement,
    /// `ZKP{S = k * T}`: first component is `S = s·G`.
    pub p_gs: Proof,
    /// Per-message inners; verified against `gt` plus the published
    /// `(S, K)` commitments.
    pub inners: Vec<VerifiableRSKInner>,
}

impl VerifiableRSKBatch {
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
        s: &ScalarNonZero,
        k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let s_k_inv = s * k.invert();
        let gt = s_k_inv * G;
        let (_gk, p_gs) = create_proof(k, &gt, rng);
        let inners = ciphertexts
            .iter()
            .map(|v| {
                VerifiableRSKInner::new(
                    v,
                    &s_k_inv,
                    s,
                    #[cfg(feature = "elgamal3")]
                    k,
                    rng,
                )
            })
            .collect();
        Self { gt, p_gs, inners }
    }

    /// Reconstruct the RSK'd ciphertexts from this batch proof,
    /// **without verifying** it. Internal prover-side use only.
    #[allow(dead_code)]
    pub(crate) fn result(&self) -> Vec<ElGamal> {
        self.inners.iter().map(|inner| inner.result()).collect()
    }

    /// Verify the hoisted `(gt, p_gs)` block once.
    #[must_use]
    pub fn verify_factor(
        &self,
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
        true
    }

    #[must_use]
    pub fn verify(
        &self,
        originals: &[ElGamal],
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        if !self.verify_factor(reshuffle_commitment, rekey_commitment) {
            return false;
        }
        if originals.len() != self.inners.len() {
            return false;
        }
        self.inners
            .iter()
            .zip(originals.iter())
            .all(|(inner, o)| inner.verify(o, &self.gt, reshuffle_commitment, rekey_commitment))
    }

    /// Verify the per-factor block and every inner against `originals`,
    /// returning the reconstructed RSK'd ciphertexts.
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal],
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> Option<Vec<ElGamal>> {
        if !self.verify_factor(reshuffle_commitment, rekey_commitment) {
            return None;
        }
        if originals.len() != self.inners.len() {
            return None;
        }
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| {
                inner.verified_reconstruct(o, &self.gt, reshuffle_commitment, rekey_commitment)
            })
            .collect()
    }

    /// Reconstruct the RSK'd ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, _originals: &[ElGamal]) -> Vec<ElGamal> {
        self.result()
    }
}

/// A batch of [`VerifiableRSK2`] proofs sharing one
/// `(s_from, s_to, k_from, k_to)` factor tuple.
///
/// Mirrors [`VerifiableRSK2`]'s layout: the per-factor `(gs, gk, p_gs_to,
/// p_gk_to)` plus an `inner` that is itself the batched VRSK over the
/// combined scalars `(s, k) = (s_from⁻¹·s_to, k_from⁻¹·k_to)`.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSK2Batch {
    /// `S = (s_from⁻¹·s_to)·G`.
    pub gs: GroupElement,
    /// `K = (k_from⁻¹·k_to)·G`.
    pub gk: GroupElement,
    /// `ZKP{S_to = s_from * S}`.
    pub p_gs_to: Proof,
    /// `ZKP{K_to = k_from * K}`.
    pub p_gk_to: Proof,
    /// VRSK batch over the combined scalars.
    pub inner: VerifiableRSKBatch,
}

impl VerifiableRSK2Batch {
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
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
        let inner = VerifiableRSKBatch::new(ciphertexts, &s, &k, rng);
        Self {
            gs,
            gk,
            p_gs_to,
            p_gk_to,
            inner,
        }
    }

    /// Reconstruct the RSK-2'd ciphertexts from this batch proof,
    /// **without verifying** it. Internal prover-side use only.
    #[allow(dead_code)]
    pub(crate) fn result(&self) -> Vec<ElGamal> {
        self.inner.result()
    }

    pub fn combined_reshuffle_commitment(&self) -> PseudonymizationFactorCommitment {
        PseudonymizationFactorCommitment(FactorCommitment(self.gs))
    }

    pub fn combined_rekey_commitment(&self) -> RekeyFactorCommitment {
        RekeyFactorCommitment(FactorCommitment(self.gk))
    }

    /// Verify all per-factor blocks (outer `(gs, gk, p_gs_to, p_gk_to)`
    /// and the inner batch's `(gt, p_gs)`) against the published
    /// `(S_from, S_to, K_from, K_to)` commitments.
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
        if *self.p_gs_to != gs_to || !verify_proof(&gs_from, &self.gs, &self.p_gs_to) {
            return false;
        }
        if *self.p_gk_to != gk_to || !verify_proof(&gk_from, &self.gk, &self.p_gk_to) {
            return false;
        }
        self.inner.verify_factor(
            &self.combined_reshuffle_commitment(),
            &self.combined_rekey_commitment(),
        )
    }

    #[must_use]
    pub fn verify(
        &self,
        originals: &[ElGamal],
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        if !self.verify_factor(
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) {
            return false;
        }
        self.inner.verify(
            originals,
            &self.combined_reshuffle_commitment(),
            &self.combined_rekey_commitment(),
        )
    }

    /// Verify all per-factor blocks and every inner against `originals`,
    /// returning the reconstructed RSK-2'd ciphertexts.
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal],
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> Option<Vec<ElGamal>> {
        if !self.verify_factor(
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) {
            return None;
        }
        self.inner.verified_reconstruct(
            originals,
            &self.combined_reshuffle_commitment(),
            &self.combined_rekey_commitment(),
        )
    }

    /// Reconstruct the RSK-2'd ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.inner.unverified_reconstruct(originals)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::{rsk, rsk2};

    fn setup_ct() -> ElGamal {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        encrypt(&m, &pk, &mut rng)
    }

    fn setup_pk_cts(n: usize) -> Vec<ElGamal> {
        (0..n).map(|_| setup_ct()).collect()
    }

    #[test]
    fn rsk_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(5);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRSKBatch::new(&cts, &s, &k, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| rsk(c, &s, &k)).collect();
        let sc = PseudonymizationFactorCommitment::new(&s);
        let kc = RekeyFactorCommitment::new(&k);
        let news = batch.verified_reconstruct(&cts, &sc, &kc).expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &sc, &kc));
    }

    #[test]
    fn rsk_batch_header_tamper_fails() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(2);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let mut batch = VerifiableRSKBatch::new(&cts, &s, &k, &mut rng);
        let sc = PseudonymizationFactorCommitment::new(&s);
        let kc = RekeyFactorCommitment::new(&k);
        batch.gt = batch.gt + GroupElement::random(&mut rng);
        assert!(!batch.verify(&cts, &sc, &kc));
    }

    #[test]
    fn rsk_batch_per_entry_works_with_header() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(3);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRSKBatch::new(&cts, &s, &k, &mut rng);
        let sc = PseudonymizationFactorCommitment::new(&s);
        let kc = RekeyFactorCommitment::new(&k);
        assert!(batch.verify(&cts, &sc, &kc));
        for (inner, o) in batch.inners.iter().zip(cts.iter()) {
            assert!(inner.verify(o, &batch.gt, &sc, &kc));
        }
    }

    #[test]
    fn rsk2_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(4);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRSK2Batch::new(&cts, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let expected_news: Vec<_> = cts
            .iter()
            .map(|c| rsk2(c, &s_from, &s_to, &k_from, &k_to))
            .collect();
        let sf = PseudonymizationFactorCommitment::new(&s_from);
        let st = PseudonymizationFactorCommitment::new(&s_to);
        let kf = RekeyFactorCommitment::new(&k_from);
        let kt = RekeyFactorCommitment::new(&k_to);
        let news = batch
            .verified_reconstruct(&cts, &sf, &st, &kf, &kt)
            .expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &sf, &st, &kf, &kt));
    }
}
