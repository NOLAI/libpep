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

use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::zkps::generic::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
/// Proof of a verifiable rerandomization: the commitment `R = r·G` and the proof that `Y_r =
/// r·Y`.
pub struct VerifiableRerandomize<G: Group> {
    /// `R = r·G`.
    pub(crate) gr: G::Element,
    /// `ZKP{Y_r = r * Y}`: first component is `Y_r = r·Y`.
    pub(crate) p_gy_r: Proof<G>,
}

impl<G: Group> VerifiableRerandomize<G> {
    /// The commitment `R = r·G`.
    pub fn gr(&self) -> &G::Element {
        &self.gr
    }
    /// The proof `ZKP{Y_r = r * Y}`.
    pub fn p_gy_r(&self) -> &Proof<G> {
        &self.p_gy_r
    }
}

impl<G: Group> VerifiableRerandomize<G> {
    /// Apply the operation and produce its proof, with randomness from `rng`.
    pub fn new<R: Rng + CryptoRng>(gy: &G::Element, r: &G::Scalar, rng: &mut R) -> Self {
        let (gr, p_gy_r) = create_proof::<G, R>(r, gy, rng);
        Self { gr, p_gy_r }
    }

    /// Reconstruct the rerandomized ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only — public callers should
    /// use [`verified_reconstruct`](Self::verified_reconstruct).
    ///
    /// `B_r = R + B`, `C_r = Y_r + C`, `Y_r = Y` (elgamal3).
    pub(crate) fn result(&self, original: &ElGamal<G>) -> ElGamal<G> {
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
    pub fn verify(&self, gy: &G::Element) -> bool {
        verify_proof::<G>(&self.gr, gy, &self.p_gy_r)
    }

    /// Verify the proof against `original` and `gy`, returning the
    /// reconstructed rerandomized ciphertext.
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal<G>,
        gy: &G::Element,
    ) -> Option<ElGamal<G>> {
        if self.verify(gy) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    pub fn unverified_reconstruct(&self, original: &ElGamal<G>) -> ElGamal<G> {
        self.result(original)
    }
}

// NOTE: `verifiable_rerandomize` is intentionally kept (not removed with the
// rest of the snake-case free wrappers) because it does extra work beyond
// `VerifiableRerandomize::new` — it also computes and returns the
// rerandomized ciphertext via the `pub(crate)` `result` helper, which is
// not otherwise accessible to external callers.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
/// Rerandomize `original` with a fresh factor and return the result with its proof.
pub fn verifiable_rerandomize<G: Group, R: Rng + CryptoRng>(
    original: &ElGamal<G>,
    r: &G::Scalar,
    rng: &mut R,
) -> (ElGamal<G>, VerifiableRerandomize<G>) {
    let proof = VerifiableRerandomize::new(&original.gy, r, rng);
    let result = proof.result(original);
    (result, proof)
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
/// Rerandomize `original` with a fresh factor and return the result with its proof; `gy` is the
/// key it is encrypted under.
pub fn verifiable_rerandomize<G: Group, R: Rng + CryptoRng>(
    original: &ElGamal<G>,
    gy: &G::Element,
    r: &G::Scalar,
    rng: &mut R,
) -> (ElGamal<G>, VerifiableRerandomize<G>) {
    let proof = VerifiableRerandomize::new(gy, r, rng);
    let result = proof.result(original);
    (result, proof)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::encrypt;
    use crate::elgamal::primitives::rerandomize;
    use crate::elgamal::verifiable::VerifiableRerandomize;
    use crate::elgamal::ElGamal;

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
