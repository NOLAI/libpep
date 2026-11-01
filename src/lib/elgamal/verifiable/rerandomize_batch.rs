//! Batched verifiable rerandomize.

use super::rerandomize::VerifiableRerandomize;
#[cfg(feature = "insecure")]
use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::Ristretto255;
#[cfg(feature = "insecure")]
use crate::elgamal::arithmetic::Ristretto255Sha512;
use crate::elgamal::arithmetic::{Ciphersuite, Group};
use crate::elgamal::ElGamal;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// Unlike the other snake-case free wrappers, `verifiable_rerandomize_batch` does extra work
// beyond `VerifiableRerandomizeBatch::new`: it also returns the rerandomized ciphertexts via the
// `pub(crate)` `result` helper, which external callers cannot reach.
#[cfg(feature = "insecure")]
/// Rerandomize every ciphertext with its own fresh factor and return the results with their batch
/// proof.
pub fn verifiable_rerandomize_batch_generic<C: Ciphersuite, R: Rng + CryptoRng>(
    originals: &[ElGamal<C::Group>],
    gy: &<C::Group as Group>::Element,
    rng: &mut R,
) -> (Vec<ElGamal<C::Group>>, VerifiableRerandomizeBatch<C::Group>) {
    let proof = VerifiableRerandomizeBatch::new::<C, _>(originals.len(), gy, rng);
    let results = proof.result(originals);
    (results, proof)
}

#[cfg(feature = "insecure")]
/// [`verifiable_rerandomize_batch_generic`] for ristretto255 with SHA-512.
pub fn verifiable_rerandomize_batch<R: Rng + CryptoRng>(
    originals: &[ElGamal],
    gy: &GroupElement,
    rng: &mut R,
) -> (Vec<ElGamal>, VerifiableRerandomizeBatch) {
    verifiable_rerandomize_batch_generic::<Ristretto255Sha512, R>(originals, gy, rng)
}

/// A batch of [`VerifiableRerandomize`] proofs sharing one recipient
/// public key `Y`.
///
/// Each entry uses a freshly sampled `r` for per-message unlinkability.
/// There is no per-batch header to hoist beyond `Y`, which lives at the
/// batch level (or in each ciphertext under `elgamal3`).
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct VerifiableRerandomizeBatch<G: Group = Ristretto255> {
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
    pub fn new<C: Ciphersuite<Group = G>, R: Rng + CryptoRng>(
        n: usize,
        gy: &G::Element,
        rng: &mut R,
    ) -> Self {
        let inners = (0..n)
            .map(|_| {
                let r = G::random_scalar(rng);
                VerifiableRerandomize::new::<C, _>(gy, &r, rng)
            })
            .collect();
        Self { inners }
    }

    /// Apply each entry's rerandomize to the corresponding ciphertext,
    /// without verifying any proofs. Internal prover-side use only.
    pub(crate) fn result(&self, originals: &[ElGamal<G>]) -> Vec<ElGamal<G>> {
        self.inners
            .iter()
            .zip(originals.iter())
            .map(|(rer, o)| rer.result(o))
            .collect()
    }

    /// Verify every entry's `ZKP{Y_r = r·Y}` against the shared `Y`.
    #[must_use]
    pub fn verify<C: Ciphersuite<Group = G>>(
        &self,
        originals: &[ElGamal<G>],
        gy: &G::Element,
    ) -> bool {
        originals.len() == self.inners.len() && self.inners.iter().all(|rer| rer.verify::<C>(gy))
    }

    reconstruct! {
        verified(originals: &[ElGamal<G>], gy: &G::Element) -> Vec<ElGamal<G>> = verify(originals, gy);
        unverified(originals: &[ElGamal<G>]) = result(originals);
    }
}
