//! Verifiable rerandomize.
//!
//! Implements the paper construction
//! `VRerandomize(⟨B, C, Y⟩, r) = ⟨R = r·G, ZKP{Y_r = r * Y}⟩` where the
//! rerandomized ciphertext is reconstructed as `⟨R + B, Y_r + C, Y⟩`.
//!
//! The verifier checks the proof `ZKP{Y_r = r * Y}`: its first component is
//! `Y_r = r·Y`, base is `Y`, commitment is `R = r·G`. No separate factor
//! commitment is needed — the proof itself is its own factor commitment.
//!
//! In `elgamal3` mode `Y` is carried by the ciphertext; in the default mode
//! the caller supplies it explicitly to the constructor and verifier.

use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRerandomize {
    /// `R = r·G`.
    pub gr: GroupElement,
    /// `ZKP{Y_r = r * Y}`: first component is `Y_r = r·Y`.
    pub p_gy_r: Proof,
}

impl VerifiableRerandomize {
    pub fn new<R: Rng + CryptoRng>(gy: &GroupElement, r: &ScalarNonZero, rng: &mut R) -> Self {
        let (gr, p_gy_r) = create_proof(r, gy, rng);
        Self { gr, p_gy_r }
    }

    /// Reconstruct the rerandomized ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only — public callers should
    /// use [`verified_reconstruct`](Self::verified_reconstruct).
    ///
    /// `B_r = R + B`, `C_r = Y_r + C`, `Y_r = Y` (elgamal3).
    pub(crate) fn result(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: self.gr + original.gb,
            gc: *self.p_gy_r + original.gc,
            #[cfg(feature = "elgamal3")]
            gy: original.gy,
        }
    }

    /// Verify the rerandomize proof against the recipient public key `gy`
    /// the original ciphertext was encrypted under.
    ///
    /// Note: rerandomize proofs are independent of the original ciphertext
    /// (the proof binds `R = r·G` to `gy` only), so no `original` argument
    /// is needed for verification.
    #[must_use]
    pub fn verify(&self, gy: &GroupElement) -> bool {
        verify_proof(&self.gr, gy, &self.p_gy_r)
    }

    /// Verify the proof against `original` and `gy`, returning the
    /// reconstructed rerandomized ciphertext.
    pub fn verified_reconstruct(&self, original: &ElGamal, gy: &GroupElement) -> Option<ElGamal> {
        if self.verify(gy) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.result(original)
    }
}

#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn verifiable_rerandomize<R: Rng + CryptoRng>(
    original: &ElGamal,
    r: &ScalarNonZero,
    rng: &mut R,
) -> (ElGamal, VerifiableRerandomize) {
    let proof = VerifiableRerandomize::new(&original.gy, r, rng);
    let result = proof.result(original);
    (result, proof)
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn verifiable_rerandomize<R: Rng + CryptoRng>(
    original: &ElGamal,
    gy: &GroupElement,
    r: &ScalarNonZero,
    rng: &mut R,
) -> (ElGamal, VerifiableRerandomize) {
    let proof = VerifiableRerandomize::new(gy, r, rng);
    let result = proof.result(original);
    (result, proof)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::G;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::rerandomize;

    fn setup_ct_and_pk() -> (ElGamal, GroupElement) {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        (encrypt(&m, &pk, &mut rng), pk)
    }

    #[test]
    fn vrr_honest_verifies() {
        let mut rng = rand::rng();
        let (c, pk) = setup_ct_and_pk();
        let r = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRerandomize::new(&pk, &r, &mut rng);
        #[cfg(feature = "elgamal3")]
        let expected = rerandomize(&c, &r);
        #[cfg(not(feature = "elgamal3"))]
        let expected = rerandomize(&c, &pk, &r);
        assert!(proof.verify(&pk));
        assert_eq!(proof.verified_reconstruct(&c, &pk), Some(expected));
    }

    #[test]
    fn vrr_tampered_proof_fails() {
        let mut rng = rand::rng();
        let (_c, pk) = setup_ct_and_pk();
        let r = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRerandomize::new(&pk, &r, &mut rng);
        proof.p_gy_r.c1 = proof.p_gy_r.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify(&pk));
    }
}
