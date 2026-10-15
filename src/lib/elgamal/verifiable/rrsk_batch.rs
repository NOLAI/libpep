//! Batched verifiable RRSK and RRSK-2.

use super::commitments::{PseudonymizationFactorCommitment, RekeyFactorCommitment};
use super::rerandomize_batch::VerifiableRerandomizeBatch;
use super::rsk_batch::{VerifiableRSK2Batch, VerifiableRSKBatch};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A batch of [`super::VerifiableRRSK`] proofs sharing one `(s, k)` factor pair.
///
/// Mirrors `VerifiableRRSK { rerandomize, rsk }` at batch level: a single
/// [`VerifiableRerandomizeBatch`] composed with a single
/// [`VerifiableRSKBatch`] over the same factor pair.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRRSKBatch<G: Group> {
    pub(crate) rerandomize: VerifiableRerandomizeBatch<G>,
    pub(crate) rsk: VerifiableRSKBatch<G>,
}

impl<G: Group> VerifiableRRSKBatch<G> {
    /// The batched rerandomize sub-proof.
    pub fn rerandomize(&self) -> &VerifiableRerandomizeBatch<G> {
        &self.rerandomize
    }
    /// The batched RSK sub-proof.
    pub fn rsk(&self) -> &VerifiableRSKBatch<G> {
        &self.rsk
    }
}

impl<G: Group> VerifiableRRSKBatch<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
        gy: &G::Element,
        s: &G::Scalar,
        k: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let rerandomize = VerifiableRerandomizeBatch::new(ciphertexts.len(), gy, rng);
        let rerandomized = rerandomize.result(ciphertexts);
        let rsk = VerifiableRSKBatch::new(&rerandomized, s, k, rng);
        Self { rerandomize, rsk }
    }

    /// Reconstruct the RRSK'd ciphertexts from this batch proof,
    /// **without verifying** it. Internal prover-side use only —
    /// public callers should use
    /// [`verified_reconstruct`](Self::verified_reconstruct).
    pub(crate) fn result(&self) -> Vec<ElGamal<G>> {
        self.rsk.result()
    }

    #[must_use]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        originals: &[ElGamal<G>],
        gy: &G::Element,
        reshuffle_commitment: &PseudonymizationFactorCommitment<G>,
        rekey_commitment: &RekeyFactorCommitment<G>,
    ) -> bool {
        if !self.rerandomize.verify(originals, gy) {
            return false;
        }
        if !self
            .rsk
            .verify_factor(reshuffle_commitment, rekey_commitment)
        {
            return false;
        }
        if originals.len() != self.rerandomize.inners.len()
            || self.rsk.inners.len() != self.rerandomize.inners.len()
        {
            return false;
        }
        let rerandomized = self.rerandomize.result(originals);
        self.rsk
            .inners
            .iter()
            .zip(rerandomized.iter())
            .all(|(inner, r)| inner.verify(r, &self.rsk.gt, reshuffle_commitment, rekey_commitment))
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], gy: &G::Element, reshuffle_commitment: &PseudonymizationFactorCommitment<G>, rekey_commitment: &RekeyFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, gy, reshuffle_commitment, rekey_commitment);
        unverified() = result();
    }
}

/// A batch of [`super::VerifiableRRSK2`] proofs sharing one
/// `(s_from, s_to, k_from, k_to)` factor tuple.
///
/// Mirrors `VerifiableRRSK2 { rerandomize, rsk2 }`.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRRSK2Batch<G: Group> {
    pub(crate) rerandomize: VerifiableRerandomizeBatch<G>,
    pub(crate) rsk2: VerifiableRSK2Batch<G>,
}

impl<G: Group> VerifiableRRSK2Batch<G> {
    /// The batched rerandomize sub-proof.
    pub fn rerandomize(&self) -> &VerifiableRerandomizeBatch<G> {
        &self.rerandomize
    }
    /// The batched RSK-2 sub-proof.
    pub fn rsk2(&self) -> &VerifiableRSK2Batch<G> {
        &self.rsk2
    }
}

impl<G: Group> VerifiableRRSK2Batch<G> {
    #[allow(clippy::too_many_arguments)]
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal<G>],
        gy: &G::Element,
        s_from: &G::Scalar,
        s_to: &G::Scalar,
        k_from: &G::Scalar,
        k_to: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let rerandomize = VerifiableRerandomizeBatch::new(ciphertexts.len(), gy, rng);
        let rerandomized = rerandomize.result(ciphertexts);
        let rsk2 = VerifiableRSK2Batch::new(&rerandomized, s_from, s_to, k_from, k_to, rng);
        Self { rerandomize, rsk2 }
    }

    /// Reconstruct the RRSK-2'd ciphertexts from this batch proof,
    /// **without verifying** it. Internal prover-side use only.
    pub(crate) fn result(&self) -> Vec<ElGamal<G>> {
        self.rsk2.inner.result()
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        originals: &[ElGamal<G>],
        gy: &G::Element,
        s_from_commitments: &PseudonymizationFactorCommitment<G>,
        s_to_commitments: &PseudonymizationFactorCommitment<G>,
        k_from_commitments: &RekeyFactorCommitment<G>,
        k_to_commitments: &RekeyFactorCommitment<G>,
    ) -> bool {
        if !self.rerandomize.verify(originals, gy) {
            return false;
        }
        if !self.rsk2.verify_factor(
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) {
            return false;
        }
        if originals.len() != self.rerandomize.inners.len()
            || self.rsk2.inner.inners.len() != self.rerandomize.inners.len()
        {
            return false;
        }
        let reshuffle_commitment = self.rsk2.combined_reshuffle_commitment();
        let rekey_commitment = self.rsk2.combined_rekey_commitment();
        let rerandomized = self.rerandomize.result(originals);
        self.rsk2
            .inner
            .inners
            .iter()
            .zip(rerandomized.iter())
            .all(|(inner, r)| {
                inner.verify(
                    r,
                    &self.rsk2.inner.gt,
                    &reshuffle_commitment,
                    &rekey_commitment,
                )
            })
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], gy: &G::Element, s_from_commitments: &PseudonymizationFactorCommitment<G>, s_to_commitments: &PseudonymizationFactorCommitment<G>, k_from_commitments: &RekeyFactorCommitment<G>, k_to_commitments: &RekeyFactorCommitment<G>) -> Vec<ElGamal<G>> = verify(originals, gy, s_from_commitments, s_to_commitments, k_from_commitments, k_to_commitments);
        unverified() = result();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::encrypt;
    use crate::elgamal::verifiable::{
        PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRRSK2Batch,
        VerifiableRRSKBatch,
    };
    use crate::elgamal::ElGamal;

    fn make_pk_ct() -> (GroupElement, ElGamal) {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        let c = encrypt(&m, &pk, &mut rng);
        (pk, c)
    }

    #[test]
    fn rrsk_batch_honest_verifies() {
        let mut rng = rand::rng();
        let (pk, c1) = make_pk_ct();
        let (_, c2) = make_pk_ct();
        let cts = vec![c1, c2];
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRRSKBatch::new(&cts, &pk, &s, &k, &mut rng);
        let expected_news = batch.result();
        let sc = PseudonymizationFactorCommitment::new(&s);
        let kc = RekeyFactorCommitment::new(&k);
        let news = batch
            .verified_reconstruct(&cts, &pk, &sc, &kc)
            .expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &pk, &sc, &kc));
    }

    #[test]
    fn rrsk_batch_tamper_fails() {
        let mut rng = rand::rng();
        let (pk, c1) = make_pk_ct();
        let (_, c2) = make_pk_ct();
        let cts = vec![c1, c2];
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let mut batch = VerifiableRRSKBatch::new(&cts, &pk, &s, &k, &mut rng);
        // Tamper an inner proof.
        batch.rsk.inners[0].p_gb_prime.c1 =
            batch.rsk.inners[0].p_gb_prime.c1 + GroupElement::random(&mut rng);
        let sc = PseudonymizationFactorCommitment::new(&s);
        let kc = RekeyFactorCommitment::new(&k);
        assert!(!batch.verify(&cts, &pk, &sc, &kc));
    }

    #[test]
    fn rrsk2_batch_honest_verifies() {
        let mut rng = rand::rng();
        let (pk, c1) = make_pk_ct();
        let (_, c2) = make_pk_ct();
        let cts = vec![c1, c2];
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRRSK2Batch::new(&cts, &pk, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let expected_news = batch.result();
        let sf = PseudonymizationFactorCommitment::new(&s_from);
        let st = PseudonymizationFactorCommitment::new(&s_to);
        let kf = RekeyFactorCommitment::new(&k_from);
        let kt = RekeyFactorCommitment::new(&k_to);
        let news = batch
            .verified_reconstruct(&cts, &pk, &sf, &st, &kf, &kt)
            .expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &pk, &sf, &st, &kf, &kt));
    }
}
