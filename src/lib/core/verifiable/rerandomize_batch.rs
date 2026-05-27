//! Batched verifiable rerandomize.

use super::rerandomize::VerifiableRerandomize;
use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "insecure")]
pub fn verifiable_rerandomize_batch<R: Rng + CryptoRng>(
    originals: &[ElGamal],
    gy: &GroupElement,
    rng: &mut R,
) -> (Vec<ElGamal>, VerifiableRerandomizeBatch) {
    let proof = VerifiableRerandomizeBatch::new(originals.len(), gy, rng);
    let results = proof.result(originals);
    (results, proof)
}

/// A batch of [`VerifiableRerandomize`] proofs sharing one recipient
/// public key `Y`.
///
/// Each entry uses a freshly sampled `r` for per-message unlinkability —
/// there is no per-batch header to hoist beyond `Y`, which lives at the
/// batch level (or in each ciphertext under `elgamal3`).
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRerandomizeBatch {
    pub inners: Vec<VerifiableRerandomize>,
}

impl VerifiableRerandomizeBatch {
    pub fn new<R: Rng + CryptoRng>(n: usize, gy: &GroupElement, rng: &mut R) -> Self {
        let inners = (0..n)
            .map(|_| {
                let r = ScalarNonZero::random(rng);
                VerifiableRerandomize::new(gy, &r, rng)
            })
            .collect();
        Self { inners }
    }

    /// Apply each entry's rerandomize to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    pub(crate) fn result(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(rer, o)| rer.result(o))
            .collect()
    }

    /// Verify every entry's `ZKP{Y_r = r·Y}` against the shared `Y`.
    #[must_use]
    pub fn verify(&self, gy: &GroupElement) -> bool {
        self.inners.iter().all(|rer| rer.verify(gy))
    }

    /// Verify every inner against `originals` and `gy`, returning the
    /// reconstructed rerandomized ciphertexts. Returns `None` on any
    /// failure (proof tampering or length mismatch).
    pub fn verified_reconstruct(
        &self,
        originals: &[ElGamal],
        gy: &GroupElement,
    ) -> Option<Vec<ElGamal>> {
        if originals.len() != self.inners.len() {
            return None;
        }
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(inner, o)| inner.verified_reconstruct(o, gy))
            .collect()
    }

    /// Reconstruct the rerandomized ciphertexts **without verifying** the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, originals: &[ElGamal]) -> Vec<ElGamal> {
        self.result(originals)
    }
}
