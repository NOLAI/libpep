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
use rand_core::{CryptoRng, RngCore};
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
    pub fn new<R: RngCore + CryptoRng>(gy: &GroupElement, r: &ScalarNonZero, rng: &mut R) -> Self {
        let (gr, p_gy_r) = create_proof(r, gy, rng);
        Self { gr, p_gy_r }
    }

    /// The rerandomized first ciphertext component, `B_r = R + B`.
    pub fn b_rerandomized(&self, original: &ElGamal) -> GroupElement {
        self.gr + original.gb
    }

    /// The rerandomized second ciphertext component, `C_r = Y_r + C`.
    pub fn c_rerandomized(&self, original: &ElGamal) -> GroupElement {
        *self.p_gy_r + original.gc
    }

    /// Rebuild the full rerandomized ciphertext.
    pub fn result(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: self.b_rerandomized(original),
            gc: self.c_rerandomized(original),
            #[cfg(feature = "elgamal3")]
            gy: original.gy,
        }
    }

    /// Verify the rerandomize proof. `gy` is the recipient public key the
    /// original ciphertext was encrypted under.
    #[must_use]
    pub fn verify(&self, gy: &GroupElement) -> bool {
        verify_proof(&self.gr, gy, &self.p_gy_r)
    }

    /// Full check: verify the proof and that `new` is the ciphertext it
    /// implicitly reconstructs.
    #[must_use]
    pub fn verify_rerandomized(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        gy: &GroupElement,
    ) -> bool {
        if !self.verify(gy) {
            return false;
        }
        if new.gb != self.b_rerandomized(original) {
            return false;
        }
        if new.gc != self.c_rerandomized(original) {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if new.gy != original.gy {
            return false;
        }
        true
    }
}

#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn verifiable_rerandomize<R: RngCore + CryptoRng>(
    original: &ElGamal,
    r: &ScalarNonZero,
    rng: &mut R,
) -> (ElGamal, VerifiableRerandomize) {
    let proof = VerifiableRerandomize::new(&original.gy, r, rng);
    let result = proof.result(original);
    (result, proof)
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn verifiable_rerandomize<R: RngCore + CryptoRng>(
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

    fn tamper(c: &ElGamal) -> ElGamal {
        let mut rng = rand::rng();
        let mut t = *c;
        t.gb = t.gb + GroupElement::random(&mut rng);
        t
    }

    #[test]
    fn vrr_honest_verifies() {
        let mut rng = rand::rng();
        let (c, pk) = setup_ct_and_pk();
        let r = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRerandomize::new(&pk, &r, &mut rng);
        #[cfg(feature = "elgamal3")]
        let result = rerandomize(&c, &r);
        #[cfg(not(feature = "elgamal3"))]
        let result = rerandomize(&c, &pk, &r);
        assert!(proof.verify_rerandomized(&c, &result, &pk));
    }

    #[test]
    fn vrr_tampered_output_fails() {
        let mut rng = rand::rng();
        let (c, pk) = setup_ct_and_pk();
        let r = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRerandomize::new(&pk, &r, &mut rng);
        #[cfg(feature = "elgamal3")]
        let real = rerandomize(&c, &r);
        #[cfg(not(feature = "elgamal3"))]
        let real = rerandomize(&c, &pk, &r);
        let bad = tamper(&real);
        assert!(!proof.verify_rerandomized(&c, &bad, &pk));
    }

    #[test]
    fn vrr_tampered_proof_fails() {
        let mut rng = rand::rng();
        let (c, pk) = setup_ct_and_pk();
        let r = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRerandomize::new(&pk, &r, &mut rng);
        #[cfg(feature = "elgamal3")]
        let result = rerandomize(&c, &r);
        #[cfg(not(feature = "elgamal3"))]
        let result = rerandomize(&c, &pk, &r);
        proof.p_gy_r.c1 = proof.p_gy_r.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify_rerandomized(&c, &result, &pk));
    }
}
