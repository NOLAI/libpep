//! Batched verifiable RSK and RSK-2.

use super::commitments::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
};
use super::rsk::VerifiableRSKInner;
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::zkps::generic::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A batch of [`super::VerifiableRSK`] proofs sharing one `(s, k)` factor pair.
///
/// `gt = (s·k⁻¹)·G` and the `ZKP{S = k·T}` ([`Self::p_gs`]) depend only on
/// `(s, k)` and not on any individual ciphertext, so they are hoisted into
/// the batch header. Each per-message [`VerifiableRSKInner`] carries only
/// the genuinely ciphertext-dependent sub-proofs.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRSKBatch<G: Group> {
    /// `T = (s·k⁻¹)·G`.
    pub(crate) gt: G::Element,
    /// `ZKP{S = k * T}`: first component is `S = s·G`.
    pub(crate) p_gs: Proof<G>,
    /// Per-message inners; verified against `gt` plus the published
    /// `(S, K)` commitments.
    pub(crate) inners: Vec<VerifiableRSKInner<G>>,
}

impl<G: Group> VerifiableRSKBatch<G> {
    /// `T = (s·k⁻¹)·G`.
    pub fn gt(&self) -> &G::Element {
        &self.gt
    }
    /// The hoisted factor sub-proof `ZKP{S = k * T}`.
    pub fn p_gs(&self) -> &Proof<G> {
        &self.p_gs
    }
    /// The per-message inner bodies.
    pub fn inners(&self) -> &[VerifiableRSKInner<G>] {
        &self.inners
    }
}

impl<G: Group> VerifiableRSKBatch<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
        s: &G::Scalar,
        k: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let s_k_inv = *s * G::scalar_inverse(k);
        let gt = s_k_inv * G::generator();
        let (_gk, p_gs) = create_proof::<G, R>(k, &gt, rng);
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
    pub(crate) fn result(&self) -> Vec<ElGamal<G>> {
        self.inners.iter().map(|inner| inner.result()).collect()
    }

    /// Verify the hoisted `(gt, p_gs)` block once.
    #[must_use]
    pub fn verify_factor(
        &self,
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
        true
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        originals: &[ElGamal<G>],
        reshuffle_commitment: &PseudonymizationFactorCommitment<G>,
        rekey_commitment: &RekeyFactorCommitment<G>,
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

    reconstruct! {
        verified(originals: &[ElGamal<G>], reshuffle_commitment: &PseudonymizationFactorCommitment<G>, rekey_commitment: &RekeyFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, reshuffle_commitment, rekey_commitment);
        unverified() = result();
    }
}

/// A batch of [`super::VerifiableRSK2`] proofs sharing one
/// `(s_from, s_to, k_from, k_to)` factor tuple.
///
/// Mirrors [`super::VerifiableRSK2`]'s layout: the per-factor `(gs, gk, p_gs_to,
/// p_gk_to)` plus an `inner` that is itself the batched VRSK over the
/// combined scalars `(s, k) = (s_from⁻¹·s_to, k_from⁻¹·k_to)`.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRSK2Batch<G: Group> {
    /// `S = (s_from⁻¹·s_to)·G`.
    pub(crate) gs: G::Element,
    /// `K = (k_from⁻¹·k_to)·G`.
    pub(crate) gk: G::Element,
    /// `ZKP{S_to = s_from * S}`.
    pub(crate) p_gs_to: Proof<G>,
    /// `ZKP{K_to = k_from * K}`.
    pub(crate) p_gk_to: Proof<G>,
    /// VRSK batch over the combined scalars.
    pub(crate) inner: VerifiableRSKBatch<G>,
}

impl<G: Group> VerifiableRSK2Batch<G> {
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
    /// The inner VRSK batch over the combined scalars.
    pub fn inner(&self) -> &VerifiableRSKBatch<G> {
        &self.inner
    }
}

impl<G: Group> VerifiableRSK2Batch<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
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
        let inner = VerifiableRSKBatch::new(ciphertexts, &s, &k, rng);
        Self {
            gs,
            gk,
            p_gs_to,
            p_gk_to,
            inner,
        }
    }

    /// The commitment to the combined reshuffle factor `s_from⁻¹·s_to`.
    pub fn combined_reshuffle_commitment(&self) -> PseudonymizationFactorCommitment<G> {
        PseudonymizationFactorCommitment(FactorCommitment(self.gs))
    }

    /// The commitment to the combined rekey factor `k_from⁻¹·k_to`.
    pub fn combined_rekey_commitment(&self) -> RekeyFactorCommitment<G> {
        RekeyFactorCommitment(FactorCommitment(self.gk))
    }

    /// Verify all per-factor blocks (outer `(gs, gk, p_gs_to, p_gk_to)`
    /// and the inner batch's `(gt, p_gs)`) against the published
    /// `(S_from, S_to, K_from, K_to)` commitments.
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
        if *self.p_gs_to != gs_to || !verify_proof::<G>(&gs_from, &self.gs, &self.p_gs_to) {
            return false;
        }
        if *self.p_gk_to != gk_to || !verify_proof::<G>(&gk_from, &self.gk, &self.p_gk_to) {
            return false;
        }
        self.inner.verify_factor(
            &self.combined_reshuffle_commitment(),
            &self.combined_rekey_commitment(),
        )
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        originals: &[ElGamal<G>],
        s_from_commitments: &PseudonymizationFactorCommitment<G>,
        s_to_commitments: &PseudonymizationFactorCommitment<G>,
        k_from_commitments: &RekeyFactorCommitment<G>,
        k_to_commitments: &RekeyFactorCommitment<G>,
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

    /// The RSK-2'd ciphertexts, **without verifying** the proof. Internal prover-side use only.
    pub(crate) fn result(&self) -> Vec<ElGamal<G>> {
        self.inner.result()
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], s_from_commitments: &PseudonymizationFactorCommitment<G>, s_to_commitments: &PseudonymizationFactorCommitment<G>, k_from_commitments: &RekeyFactorCommitment<G>, k_to_commitments: &RekeyFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, s_from_commitments, s_to_commitments, k_from_commitments, k_to_commitments);
        unverified() = result();
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
        PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRSK2Batch,
        VerifiableRSKBatch,
    };
    use crate::elgamal::ElGamal;

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
