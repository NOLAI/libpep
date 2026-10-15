//! Batched verifiable rerandomize.

use super::rerandomize::VerifiableRerandomize;
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// NOTE: `verifiable_rerandomize_batch` is intentionally kept (not removed
// with the rest of the snake-case free wrappers) because it does extra
// work beyond `VerifiableRerandomizeBatch::new` — it also returns the
// rerandomized ciphertexts via the `pub(crate)` `result` helper, which is
// not otherwise accessible to external callers.
#[cfg(feature = "insecure")]
/// Rerandomize every ciphertext with its own fresh factor and return the results with their batch
/// proof.
pub fn verifiable_rerandomize_batch<G: Group, R: Rng + CryptoRng>(
    originals: &[ElGamal<G>],
    gy: &G::Element,
    rng: &mut R,
) -> (Vec<ElGamal<G>>, VerifiableRerandomizeBatch<G>) {
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRerandomizeBatch<G: Group> {
    pub(crate) inners: Vec<VerifiableRerandomize<G>>,
}

impl<G: Group> VerifiableRerandomizeBatch<G> {
    /// The per-message inner proofs.
    pub fn inners(&self) -> &[VerifiableRerandomize<G>] {
        &self.inners
    }
}

impl<G: Group> VerifiableRerandomizeBatch<G> {
    /// Fresh rerandomization proofs for `n` ciphertexts encrypted under `gy`.
    pub fn new<R: Rng + CryptoRng>(n: usize, gy: &G::Element, rng: &mut R) -> Self {
        let inners = (0..n)
            .map(|_| {
                let r = G::random_scalar(rng);
                VerifiableRerandomize::new(gy, &r, rng)
            })
            .collect();
        Self { inners }
    }

    /// Apply each entry's rerandomize to the corresponding ciphertext,
    /// **without verifying** any proofs. Internal prover-side use only.
    pub(crate) fn result(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(rer, o)| rer.result(o))
            .collect()
    }

    /// Verify every entry's `ZKP{Y_r = r·Y}` against the shared `Y`.
    #[must_use]
    pub fn verify(&self, originals: &[ElGamal<G>], gy: &G::Element) -> bool {
        originals.len() == self.inners.len() && self.inners.iter().all(|rer| rer.verify(gy))
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], gy: &G::Element) -> Vec<ElGamal<G>> = verify(originals, gy);
        unverified(originals: &[ElGamal<G>]) = result(originals);
    }
}
