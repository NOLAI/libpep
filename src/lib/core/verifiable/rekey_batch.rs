//! Batched verifiable rekey and rekey-2.

use super::commitments::{FactorCommitment, RekeyFactorCommitment};
use super::rekey::VerifiableRekey;
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub fn verifiable_rekey_batch<R: Rng + CryptoRng>(
    ciphertexts: &[ElGamal],
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekeyBatch {
    VerifiableRekeyBatch::new(ciphertexts, k, rng)
}

pub fn verifiable_rekey2_batch<R: Rng + CryptoRng>(
    ciphertexts: &[ElGamal],
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekey2Batch {
    VerifiableRekey2Batch::new(ciphertexts, k_from, k_to, rng)
}

/// A batch of [`VerifiableRekey`] proofs sharing one rekey factor.
///
/// No header is needed: the rekey-factor commitment `K = k·G` is supplied
/// by the verifier as part of the published per-transition commitments.
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRekeyBatch {
    pub inners: Vec<VerifiableRekey>,
}

impl VerifiableRekeyBatch {
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
        k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        Self {
            inners: ciphertexts
                .iter()
                .map(|v| VerifiableRekey::new(v, k, rng))
                .collect(),
        }
    }

    /// Apply each entry's rekey to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    #[allow(dead_code)]
    pub(crate) fn result(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    /// Verify the whole batch against `originals`.
    #[must_use]
    pub fn verify(&self, originals: &[ElGamal], commitment: &RekeyFactorCommitment) -> bool {
        originals.len() == self.inners.len()
            && self
                .inners
                .iter()
                .zip(originals.iter())
                .all(|(inner, o)| inner.verify(o, commitment))
    }

    /// Verify every inner against `originals` and return the reconstructed
    /// rekeyed ciphertexts. Returns `None` if any inner fails to verify or
    /// if `originals.len()` mismatches the batch length.
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal],
        commitment: &RekeyFactorCommitment,
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

    /// Reconstruct the rekeyed ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.result(originals)
    }
}

/// A batch of [`VerifiableRekey2`] proofs sharing one `(k_from, k_to)` factor pair.
///
/// Mirrors [`VerifiableRekey2`]'s layout (`gk`, `p_gk_to`, `inner: VerifiableRekey`)
/// at batch level — the inner scalar `k = k_from⁻¹·k_to` is hoisted into the
/// single `gk`/`p_gk_to` pair, and the per-message inners are still ordinary
/// [`VerifiableRekey`] values that verify against [`Self::combined_commitment`].
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRekey2Batch {
    /// `K = (k_from⁻¹·k_to)·G`.
    pub gk: GroupElement,
    /// `ZKP{K_to = k_from * K}`.
    pub p_gk_to: Proof,
    /// One [`VerifiableRekey`] per ciphertext, under the combined scalar.
    pub inners: Vec<VerifiableRekey>,
}

impl VerifiableRekey2Batch {
    pub fn new<R: Rng + CryptoRng>(
        ciphertexts: &[ElGamal],
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let k = k_from.invert() * k_to;
        let gk = k * G;
        let (_gk_from, p_gk_to) = create_proof(k_from, &gk, rng);
        let inners = ciphertexts
            .iter()
            .map(|v| VerifiableRekey::new(v, &k, rng))
            .collect();
        Self {
            gk,
            p_gk_to,
            inners,
        }
    }

    /// Apply each entry's rekey to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    #[allow(dead_code)]
    pub(crate) fn result(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.result(o))
            .collect()
    }

    /// The combined commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn combined_commitment(&self) -> RekeyFactorCommitment {
        RekeyFactorCommitment(FactorCommitment(self.gk))
    }

    /// Verify the hoisted `(gk, p_gk_to)` block once against the published
    /// `K_from`, `K_to` commitments. After this passes, every inner can be
    /// verified against [`Self::combined_commitment`].
    #[must_use]
    pub fn verify_factor(
        &self,
        from_commitments: &RekeyFactorCommitment,
        to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        let gk_from = from_commitments.0 .0;
        let gk_to = to_commitments.0 .0;
        *self.p_gk_to == gk_to && verify_proof(&gk_from, &self.gk, &self.p_gk_to)
    }

    #[must_use]
    pub fn verify(
        &self,
        originals: &[ElGamal],
        from_commitments: &RekeyFactorCommitment,
        to_commitments: &RekeyFactorCommitment,
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
    /// returning the reconstructed rekeyed ciphertexts. Returns `None` if
    /// any verification step fails or if `originals.len()` mismatches.
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal],
        from_commitments: &RekeyFactorCommitment,
        to_commitments: &RekeyFactorCommitment,
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

    /// Reconstruct the rekeyed ciphertexts **without verifying** the proof.
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
    use crate::core::primitives::{rekey, rekey2};

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
    fn rekey_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(5);
        let k = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRekeyBatch::new(&cts, &k, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| rekey(c, &k)).collect();
        let com = RekeyFactorCommitment::new(&k);
        let news = batch.verified_reconstruct(&cts, &com).expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &com));
    }

    #[test]
    fn rekey_batch_tampered_proof_fails() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(3);
        let k = ScalarNonZero::random(&mut rng);
        let mut batch = VerifiableRekeyBatch::new(&cts, &k, &mut rng);
        // Tamper an inner proof's response.
        batch.inners[1].p_gb.c1 = batch.inners[1].p_gb.c1 + GroupElement::random(&mut rng);
        let com = RekeyFactorCommitment::new(&k);
        assert!(!batch.verify(&cts, &com));
        assert!(batch.verified_reconstruct(&cts, &com).is_none());
    }

    #[test]
    fn rekey2_batch_honest_verifies() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(5);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let batch = VerifiableRekey2Batch::new(&cts, &k_from, &k_to, &mut rng);
        let expected_news: Vec<_> = cts.iter().map(|c| rekey2(c, &k_from, &k_to)).collect();
        let from = RekeyFactorCommitment::new(&k_from);
        let to = RekeyFactorCommitment::new(&k_to);
        let news = batch
            .verified_reconstruct(&cts, &from, &to)
            .expect("verify");
        assert_eq!(news, expected_news);
        assert!(batch.verify(&cts, &from, &to));
    }

    #[test]
    fn rekey2_batch_factor_tamper_fails() {
        let mut rng = rand::rng();
        let cts = setup_pk_cts(2);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let mut batch = VerifiableRekey2Batch::new(&cts, &k_from, &k_to, &mut rng);
        let from = RekeyFactorCommitment::new(&k_from);
        let to = RekeyFactorCommitment::new(&k_to);
        batch.gk = batch.gk + GroupElement::random(&mut rng);
        assert!(!batch.verify(&cts, &from, &to));
    }
}
