use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// RERANDOMIZE
// We are re-using some variables from the Proof to reconstruct the Rerandomize operation.
// This way, we only need 1 Proof object (which are fairly large)
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRerandomize(GroupElement, Proof);

impl VerifiableRerandomize {
    pub fn new<R: RngCore + CryptoRng>(original: &ElGamal, r: &ScalarNonZero, rng: &mut R) -> Self {
        // Rerandomize is normally {r * G + in.b, r*in.y + in.c, in.y};
        let (gr, p) = create_proof(r, &original.gy, rng);
        Self(gr, p)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal) -> Option<ElGamal> {
        if self.verify(original) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: self.0 + original.gb,
            gc: *self.1 + original.gc,
            gy: original.gy,
        }
    }
    #[must_use]
    fn verify(&self, original: &ElGamal) -> bool {
        Self::verify_split(&original.gb, &original.gc, &original.gy, &self.0, &self.1)
    }
    #[must_use]
    pub fn verify_rerandomized(&self, original: &ElGamal, new: &ElGamal) -> bool {
        self.verify(original)
            && new.gb == self.0 + original.gb
            && new.gc == *self.1 + original.gc
            && new.gy == original.gy
    }
    #[must_use]
    fn verify_split(
        _gb: &GroupElement,
        _gc: &GroupElement,
        gy: &GroupElement,
        gr: &GroupElement,
        p: &Proof,
    ) -> bool {
        // slightly different from the others, as we reuse the structure of a standard proof to reconstruct the Rerandomize operation after sending
        verify_proof(gr, gy, p)
    }
}

pub fn verifiable_rerandomize<R: RngCore + CryptoRng>(
    original: &ElGamal,
    r: &ScalarNonZero,
    rng: &mut R,
) -> (ElGamal, VerifiableRerandomize) {
    let verifiable_rerandomize = VerifiableRerandomize::new(original, r, rng);
    let rerandomized = verifiable_rerandomize.reconstruct(original);
    (rerandomized, verifiable_rerandomize)
}
