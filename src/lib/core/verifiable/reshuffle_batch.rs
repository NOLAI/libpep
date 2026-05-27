//! Batched verifiable reshuffle and reshuffle-2.

use super::commitments::{FactorCommitment, PseudonymizationFactorCommitment};
use super::reshuffle::VerifiableReshuffle;
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub fn verifiable_reshuffle_batch<R: Rng + CryptoRng>(
    ciphertexts: &[ElGamal],
    s: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffleBatch {
    VerifiableReshuffleBatch::new(ciphertexts, s, rng)
}

pub fn verifiable_reshuffle2_batch<R: Rng + CryptoRng>(
    ciphertexts: &[ElGamal],
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffle2Batch {
    VerifiableReshuffle2Batch::new(ciphertexts, s_from, s_to, rng)
}

/// A batch of [`VerifiableReshuffle`] proofs sharing one reshuffle factor.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableReshuffleBatch {
    pub inners: Vec<VerifiableReshuffle>,
}

impl VerifiableReshuffleBatch {
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
        s: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        Self {
            inners: ciphertexts
                .iter()
                .map(|v| VerifiableReshuffle::new(v, s, rng))
                .collect(),
        }
    }

    /// Apply each entry's reshuffle to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    #[allow(dead_code)]
    pub(crate) fn result(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    #[must_use]
    pub fn verify(
        &self,
        originals: &[ElGamal],
        commitment: &PseudonymizationFactorCommitment,
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
        originals: &[ElGamal],
        commitment: &PseudonymizationFactorCommitment,
    ) -> Option<Vec<ElGamal>> {
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
    pub fn unverified_reconstruct(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.result(originals)
    }
}

/// A batch of [`VerifiableReshuffle2`] proofs sharing one `(s_from, s_to)`
/// factor pair.
///
/// Mirrors [`VerifiableReshuffle2`]'s layout (`gs`, `p_gs_to`, `inner:
/// VerifiableReshuffle`) at batch level.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableReshuffle2Batch {
    pub gs: GroupElement,
    pub p_gs_to: Proof,
    pub inners: Vec<VerifiableReshuffle>,
}

impl VerifiableReshuffle2Batch {
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let s = s_from.invert() * s_to;
        let gs = s * G;
        let (_gs_from, p_gs_to) = create_proof(s_from, &gs, rng);
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
    #[allow(dead_code)]
    pub(crate) fn result(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    pub fn combined_commitment(&self) -> PseudonymizationFactorCommitment {
        PseudonymizationFactorCommitment(FactorCommitment(self.gs))
    }

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

    #[must_use]
    pub fn verify(
        &self,
        originals: &[ElGamal],
        from_commitments: &PseudonymizationFactorCommitment,
        to_commitments: &PseudonymizationFactorCommitment,
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
        originals: &[ElGamal],
        from_commitments: &PseudonymizationFactorCommitment,
        to_commitments: &PseudonymizationFactorCommitment,
    ) -> Option<Vec<ElGamal>> {
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
    pub fn unverified_reconstruct(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.result(originals)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::{reshuffle, reshuffle2};

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
