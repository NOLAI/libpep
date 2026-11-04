//! Batched verifiable reshuffle and reshuffle-2.

use super::commitments::{FactorCommitment, PseudonymizationFactorCommitment};
use super::reshuffle::VerifiableReshuffle;
use crate::ciphersuite::Ciphersuite;
use crate::elgamal::zkps::{create_proof, verify_proof, Proof};
use crate::elgamal::ElGamal;
use crate::group::Group;
use crate::group::Ristretto255;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A batch of [`VerifiableReshuffle`] proofs sharing one reshuffle factor.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableReshuffleBatch<G: Group = Ristretto255> {
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
    pub fn new<C: Ciphersuite<Group = G>, R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
        s: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        Self {
            inners: ciphertexts
                .iter()
                .map(|v| VerifiableReshuffle::new::<C, _>(v, s, rng))
                .collect(),
        }
    }

    /// Apply each entry's reshuffle to the corresponding ciphertext,
    /// without verifying any proofs. Internal prover-side use only.
    pub(crate) fn result(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify<C: Ciphersuite<Group = G>>(
        &self,
        originals: &[ElGamal<G>],
        commitment: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        originals.len() == self.inners.len()
            && self
                .inners
                .iter()
                .zip(originals.iter())
                .all(|(inner, o)| inner.verify::<C>(o, commitment))
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], commitment: &PseudonymizationFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, commitment);
        unverified(originals: &[ElGamal<G>]) = result(originals);
    }
}

/// A batch of [`super::VerifiableReshuffle2`] proofs sharing one `(s_from, s_to)`
/// factor pair.
///
/// Mirrors [`super::VerifiableReshuffle2`]'s layout (`gs`, `p_gs_to`, `inner:
/// VerifiableReshuffle`) at batch level.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableReshuffle2Batch<G: Group = Ristretto255> {
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
    pub fn new<C: Ciphersuite<Group = G>, R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
        s_from: &G::Scalar,
        s_to: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let s = G::scalar_inverse(s_from) * *s_to;
        let gs = s * G::generator();
        let (_gs_from, p_gs_to) = create_proof::<C, R>(s_from, &gs, rng);
        let inners = ciphertexts
            .iter()
            .map(|v| VerifiableReshuffle::new::<C, _>(v, &s, rng))
            .collect();
        Self {
            gs,
            p_gs_to,
            inners,
        }
    }

    /// Apply each entry's reshuffle to the corresponding ciphertext,
    /// without verifying any proofs. Internal prover-side use only.
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
    pub fn verify_factor<C: Ciphersuite<Group = G>>(
        &self,
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        let gs_from = from_commitments.point();
        let gs_to = to_commitments.point();
        *self.p_gs_to == gs_to && verify_proof::<C>(&gs_from, &self.gs, &self.p_gs_to)
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify<C: Ciphersuite<Group = G>>(
        &self,
        originals: &[ElGamal<G>],
        from_commitments: &PseudonymizationFactorCommitment<G>,
        to_commitments: &PseudonymizationFactorCommitment<G>,
    ) -> bool {
        if !self.verify_factor::<C>(from_commitments, to_commitments) {
            return false;
        }
        if originals.len() != self.inners.len() {
            return false;
        }
        let commitment = self.combined_commitment();
        self.inners
            .iter()
            .zip(originals.iter())
            .all(|(inner, o)| inner.verify::<C>(o, &commitment))
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], from_commitments: &PseudonymizationFactorCommitment<G>, to_commitments: &PseudonymizationFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, from_commitments, to_commitments);
        unverified(originals: &[ElGamal<G>]) = result(originals);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::ciphersuite::Ristretto255Sha512;
    use crate::elgamal::primitives::{reshuffle, reshuffle2};
    use crate::elgamal::test_util::encrypt;
    use crate::elgamal::test_util::ElGamal;
    use crate::elgamal::verifiable::{
        PseudonymizationFactorCommitment, VerifiableReshuffle2Batch, VerifiableReshuffleBatch,
    };
    use crate::group::elements::{GroupElement, G};
    use crate::group::scalars::ScalarNonZero;

    type C = Ristretto255Sha512;

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
        let batch = VerifiableReshuffleBatch::new::<C, _>(&cts, &s, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| reshuffle(c, &s)).collect();
        let com = PseudonymizationFactorCommitment::new(&s);
        let news = batch.verified_reconstruct::<C>(&cts, &com).expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify::<C>(&cts, &com));
    }

    #[test]
    fn reshuffle2_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(3);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let batch = VerifiableReshuffle2Batch::new::<C, _>(&cts, &s_from, &s_to, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| reshuffle2(c, &s_from, &s_to)).collect();
        let from = PseudonymizationFactorCommitment::new(&s_from);
        let to = PseudonymizationFactorCommitment::new(&s_to);
        let news = batch
            .verified_reconstruct::<C>(&cts, &from, &to)
            .expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify::<C>(&cts, &from, &to));
    }
}
