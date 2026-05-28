//! Batched verifiable RRSK and RRSK-2.

use super::commitments::{PseudonymizationFactorCommitment, RekeyFactorCommitment};
use super::rerandomize_batch::VerifiableRerandomizeBatch;
use super::rsk_batch::{VerifiableRSK2Batch, VerifiableRSKBatch};
use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A batch of [`super::VerifiableRRSK`] proofs sharing one `(s, k)` factor pair.
///
/// Mirrors `VerifiableRRSK { rerandomize, rsk }` at batch level: a single
/// [`VerifiableRerandomizeBatch`] composed with a single
/// [`VerifiableRSKBatch`] over the same factor pair.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRRSKBatch {
    pub(crate) rerandomize: VerifiableRerandomizeBatch,
    pub(crate) rsk: VerifiableRSKBatch,
}

impl VerifiableRRSKBatch {
    /// The batched rerandomize sub-proof.
    pub fn rerandomize(&self) -> &VerifiableRerandomizeBatch {
        &self.rerandomize
    }
    /// The batched RSK sub-proof.
    pub fn rsk(&self) -> &VerifiableRSKBatch {
        &self.rsk
    }
}

impl VerifiableRRSKBatch {
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
        gy: &GroupElement,
        s: &ScalarNonZero,
        k: &ScalarNonZero,
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
    pub(crate) fn result(&self) -> Vec<ElGamal> {
        self.rsk.result()
    }

    #[must_use]
    pub fn verify(
        &self,
        originals: &[ElGamal],
        gy: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        if !self.rerandomize.verify(gy) {
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

    /// Verify the rerandomize batch, the RSK per-factor block, and every
    /// inner against `originals`, returning the reconstructed RRSK'd
    /// ciphertexts.
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal],
        gy: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> Option<Vec<ElGamal>> {
        if !self
            .rsk
            .verify_factor(reshuffle_commitment, rekey_commitment)
        {
            return None;
        }
        if self.rsk.inners.len() != self.rerandomize.inners.len() {
            return None;
        }
        let rerandomized = self.rerandomize.verified_reconstruct(originals, gy)?;
        self.rsk
            .inners
            .iter()
            .zip(rerandomized.iter())
            .map(|(inner, r)| {
                inner.verified_reconstruct(r, &self.rsk.gt, reshuffle_commitment, rekey_commitment)
            })
            .collect()
    }

    /// Reconstruct the RRSK'd ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, _originals: &[ElGamal]) -> Vec<ElGamal> {
        self.result()
    }
}

/// A batch of [`super::VerifiableRRSK2`] proofs sharing one
/// `(s_from, s_to, k_from, k_to)` factor tuple.
///
/// Mirrors `VerifiableRRSK2 { rerandomize, rsk2 }`.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRRSK2Batch {
    pub(crate) rerandomize: VerifiableRerandomizeBatch,
    pub(crate) rsk2: VerifiableRSK2Batch,
}

impl VerifiableRRSK2Batch {
    /// The batched rerandomize sub-proof.
    pub fn rerandomize(&self) -> &VerifiableRerandomizeBatch {
        &self.rerandomize
    }
    /// The batched RSK-2 sub-proof.
    pub fn rsk2(&self) -> &VerifiableRSK2Batch {
        &self.rsk2
    }
}

impl VerifiableRRSK2Batch {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
        gy: &GroupElement,
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let rerandomize = VerifiableRerandomizeBatch::new(ciphertexts.len(), gy, rng);
        let rerandomized = rerandomize.result(ciphertexts);
        let rsk2 = VerifiableRSK2Batch::new(&rerandomized, s_from, s_to, k_from, k_to, rng);
        Self { rerandomize, rsk2 }
    }

    /// Reconstruct the RRSK-2'd ciphertexts from this batch proof,
    /// **without verifying** it. Internal prover-side use only.
    #[allow(dead_code)]
    pub(crate) fn result(&self) -> Vec<ElGamal> {
        self.rsk2.inner.result()
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        originals: &[ElGamal],
        gy: &GroupElement,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        if !self.rerandomize.verify(gy) {
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

    /// Verify the rerandomize batch, all per-factor blocks, and every
    /// inner against `originals`, returning the reconstructed RRSK-2'd
    /// ciphertexts.
    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal],
        gy: &GroupElement,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> Option<Vec<ElGamal>> {
        if !self.rsk2.verify_factor(
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) {
            return None;
        }
        if self.rsk2.inner.inners.len() != self.rerandomize.inners.len() {
            return None;
        }
        let reshuffle_commitment = self.rsk2.combined_reshuffle_commitment();
        let rekey_commitment = self.rsk2.combined_rekey_commitment();
        let rerandomized = self.rerandomize.verified_reconstruct(originals, gy)?;
        self.rsk2
            .inner
            .inners
            .iter()
            .zip(rerandomized.iter())
            .map(|(inner, r)| {
                inner.verified_reconstruct(
                    r,
                    &self.rsk2.inner.gt,
                    &reshuffle_commitment,
                    &rekey_commitment,
                )
            })
            .collect()
    }

    /// Reconstruct the RRSK-2'd ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, _originals: &[ElGamal]) -> Vec<ElGamal> {
        self.result()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::G;
    use crate::core::elgamal::encrypt;

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
