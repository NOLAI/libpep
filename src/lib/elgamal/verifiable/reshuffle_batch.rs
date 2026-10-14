//! Batched verifiable reshuffle and reshuffle-2.

use super::commitments::{FactorCommitment, PseudonymizationFactorCommitment};
use super::reshuffle::VerifiableReshuffle;
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::zkps::generic::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A batch of [`VerifiableReshuffle`] proofs sharing one reshuffle factor.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableReshuffleBatch<G: Group> {
    pub(crate) inners: Vec<VerifiableReshuffle<G>>,
}

impl<G: Group> VerifiableReshuffleBatch<G> {
    /// The per-message inner proofs.
    pub fn inners(&self) -> &[VerifiableReshuffle<G>] {
        &self.inners
    }
}

impl<G: Group> VerifiableReshuffleBatch<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(ciphertexts: &[ElGamal<G>], s: &G::Scalar, rng: &mut R) -> Self {
        Self {
            inners: ciphertexts
                .iter()
                .map(|v| VerifiableReshuffle::new(v, s, rng))
                .collect(),
        }
    }

    /// Apply each entry's reshuffle to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    #[cfg(feature = "insecure")]
    pub(crate) fn result(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        originals: &[ElGamal<G>],
        commitment: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        originals.len() == self.inners.len()
            && self
                .inners
                .iter()
                .zip(originals.iter())
                .all(|(inner, o)| inner.verify(o, commitment))
    }

    /// Verify every inner against `originals` and return the reconstructed
    /// reshuffled ciphertexts. Returns `None` on any failure.
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal<G>],
        commitment: &PseudonymizationFactorCommitment<G>,
    ) -> Option<Vec<ElGamal<G>>> {
        if originals.len() != self.inners.len() {
            return None;
        }
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.verified_reconstruct(o, commitment))
            .collect()
    }

    /// Reconstruct the reshuffled ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.result(originals)
    }
}

/// A batch of [`super::VerifiableReshuffle2`] proofs sharing one `(s_from, s_to)`
/// factor pair.
///
/// Mirrors [`super::VerifiableReshuffle2`]'s layout (`gs`, `p_gs_to`, `inner:
/// VerifiableReshuffle`) at batch level.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableReshuffle2Batch<G: Group> {
    pub(crate) gs: G::Element,
    pub(crate) p_gs_to: Proof<G>,
    pub(crate) inners: Vec<VerifiableReshuffle<G>>,
}

impl<G: Group> VerifiableReshuffle2Batch<G> {
    /// The combined commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn gs(&self) -> &G::Element {
        &self.gs
    }
    /// The per-factor sub-proof `ZKP{S_to = s_from * S}`.
    pub fn p_gs_to(&self) -> &Proof<G> {
        &self.p_gs_to
    }
    /// The per-message inner proofs.
    pub fn inners(&self) -> &[VerifiableReshuffle<G>] {
        &self.inners
    }
}

impl<G: Group> VerifiableReshuffle2Batch<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
        s_from: &G::Scalar,
        s_to: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let s = G::scalar_inverse(s_from) * *s_to;
        let gs = s * G::generator();
        let (_gs_from, p_gs_to) = create_proof::<G, R>(s_from, &gs, rng);
        let inners = ciphertexts
            .iter()
            .map(|v| VerifiableReshuffle::new(v, &s, rng))
            .collect();
        Self {
            gs,
            p_gs_to,
            inners,
        }
    }

    /// Apply each entry's reshuffle to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    #[cfg(feature = "insecure")]
    pub(crate) fn result(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    /// The commitment to the combined factor `s_from⁻¹·s_to`.
    pub fn combined_commitment(&self) -> PseudonymizationFactorCommitment<G> {
        PseudonymizationFactorCommitment(FactorCommitment(self.gs))
    }

    #[must_use]
    /// Verify the part of the proof that depends only on the factors, shared by every item.
    pub fn verify_factor(
        &self,
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        let gs_from = from_commitments.point();
        let gs_to = to_commitments.point();
        *self.p_gs_to == gs_to && verify_proof::<G>(&gs_from, &self.gs, &self.p_gs_to)
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        originals: &[ElGamal<G>],
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        if !self.verify_factor(from_commitments, to_commitments) {
            return false;
        }
        if originals.len() != self.inners.len() {
            return false;
        }
        let commitment = self.combined_commitment();
        self.inners
            .iter()
            .zip(originals.iter())
            .all(|(inner, o)| inner.verify(o, &commitment))
    }

    /// Verify the per-factor block and every inner against `originals`,
    /// returning the reconstructed reshuffled ciphertexts.
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal<G>],
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> Option<Vec<ElGamal<G>>> {
        if !self.verify_factor(from_commitments, to_commitments) {
            return None;
        }
        if originals.len() != self.inners.len() {
            return None;
        }
        let commitment = self.combined_commitment();
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.verified_reconstruct(o, &commitment))
            .collect()
    }

    /// Reconstruct the reshuffled ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.result(originals)
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
        PseudonymizationFactorCommitment, VerifiableReshuffle2Batch, VerifiableReshuffleBatch,
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
    fn reshuffle_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(4);
        let s = ScalarNonZero::random(&mut rng);
        let batch = VerifiableReshuffleBatch::new(&cts, &s, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| reshuffle(c, &s)).collect();
        let com = PseudonymizationFactorCommitment::new(&s);
        let news = batch.verified_reconstruct(&cts, &com).expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &com));
    }

    #[test]
    fn reshuffle2_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(3);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let batch = VerifiableReshuffle2Batch::new(&cts, &s_from, &s_to, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| reshuffle2(c, &s_from, &s_to)).collect();
        let from = PseudonymizationFactorCommitment::new(&s_from);
        let to = PseudonymizationFactorCommitment::new(&s_to);
        let news = batch
            .verified_reconstruct(&cts, &from, &to)
            .expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &from, &to));
    }
}
