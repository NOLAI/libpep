//! Verifiable rerandomize.
//!
//! Implements the verifiable rerandomize, VRR:
//! `VRerandomize(⟨B, C, Y⟩, r) = ⟨R = r·G, ZKP{Y_r = r * Y}⟩` where the
//! rerandomized ciphertext is reconstructed as `⟨R + B, Y_r + C, Y⟩`.
//!
//! The verifier checks the proof `ZKP{Y_r = r * Y}`: its first component is
//! `Y_r = r·Y`, base is `Y`, commitment is `R = r·G`. No separate factor
//! commitment is needed: the proof itself is its own factor commitment.
//!
//! In `elgamal3` mode `Y` is carried by the ciphertext; in the default mode
//! the caller supplies it explicitly to the constructor and verifier.

use crate::ciphersuite::Ciphersuite;
#[cfg(feature = "insecure")]
use crate::ciphersuite::Ristretto255Sha512;
use crate::elgamal::zkps::{create_proof, verify_proof, Proof};
use crate::elgamal::ElGamal;
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
use crate::group::group_elements::GroupElement;
#[cfg(feature = "insecure")]
use crate::group::scalars::ScalarNonZero;
use crate::group::Group;
use crate::group::Ristretto255;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
/// Proof of a verifiable rerandomization: the commitment `R = r·G` and the proof that `Y_r =
/// r·Y`.
pub struct VerifiableRerandomize<G: Group = Ristretto255> {
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
    pub fn new<C: Ciphersuite<Group = G>, R: Rng + CryptoRng>(
        gy: &G::Element,
        r: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let (gr, p_gy_r) = create_proof::<C, R>(r, gy, rng);
        Self { gr, p_gy_r }
    }

    /// Reconstruct the rerandomized ciphertext from this proof, without
    /// verifying it. Internal prover-side use only; public callers should
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

    /// Verify the rerandomize proof against the public key `gy`
    /// the original ciphertext was encrypted under.
    ///
    /// Rerandomize proofs are independent of the original ciphertext
    /// (the proof binds `R = r·G` to `gy` only), so no `original` argument
    /// is needed for verification.
    #[must_use]
    pub fn verify<C: Ciphersuite<Group = G>>(&self, gy: &G::Element) -> bool {
        verify_proof::<C>(&self.gr, gy, &self.p_gy_r)
    }

    reconstruct! {
        verified(original: &ElGamal<G>, gy: &G::Element) -> ElGamal<G> = verify(gy);
        unverified(original: &ElGamal<G>) = result(original);
    }
}

// Unlike the other snake-case free wrappers, `verifiable_rerandomize` does extra work beyond
// `VerifiableRerandomize::new`: it also computes and returns the rerandomized ciphertext via
// the `pub(crate)` `result` helper, which external callers cannot reach.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
/// Rerandomize `original` with a fresh factor and return the result with its proof.
pub fn verifiable_rerandomize_generic<C: Ciphersuite, R: Rng + CryptoRng>(
    original: &ElGamal<C::Group>,
    r: &<C::Group as Group>::Scalar,
    rng: &mut R,
) -> (ElGamal<C::Group>, VerifiableRerandomize<C::Group>) {
    let proof = VerifiableRerandomize::new::<C, _>(&original.gy, r, rng);
    let result = proof.result(original);
    (result, proof)
}

#[cfg(all(feature = "insecure", feature = "elgamal3"))]
/// [`verifiable_rerandomize_generic`] for ristretto255 with SHA-512.
pub fn verifiable_rerandomize<R: Rng + CryptoRng>(
    original: &ElGamal,
    r: &ScalarNonZero,
    rng: &mut R,
) -> (ElGamal, VerifiableRerandomize) {
    verifiable_rerandomize_generic::<Ristretto255Sha512, R>(original, r, rng)
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
/// Rerandomize `original` with a fresh factor and return the result with its proof; `gy` is the
/// key it is encrypted under.
pub fn verifiable_rerandomize_generic<C: Ciphersuite, R: Rng + CryptoRng>(
    original: &ElGamal<C::Group>,
    gy: &<C::Group as Group>::Element,
    r: &<C::Group as Group>::Scalar,
    rng: &mut R,
) -> (ElGamal<C::Group>, VerifiableRerandomize<C::Group>) {
    let proof = VerifiableRerandomize::new::<C, _>(gy, r, rng);
    let result = proof.result(original);
    (result, proof)
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
/// [`verifiable_rerandomize_generic`] for ristretto255 with SHA-512.
pub fn verifiable_rerandomize<R: Rng + CryptoRng>(
    original: &ElGamal,
    gy: &GroupElement,
    r: &ScalarNonZero,
    rng: &mut R,
) -> (ElGamal, VerifiableRerandomize) {
    verifiable_rerandomize_generic::<Ristretto255Sha512, R>(original, gy, r, rng)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::ciphersuite::Ristretto255Sha512;
    use crate::elgamal::primitives::rerandomize;
    use crate::elgamal::test_util::encrypt;
    use crate::elgamal::test_util::ElGamal;
    use crate::group::group_elements::{GroupElement, G};
    use crate::group::scalars::ScalarNonZero;
    use crate::group::Ristretto255;

    type C = Ristretto255Sha512;

    type VerifiableRerandomize = crate::elgamal::verifiable::VerifiableRerandomize<Ristretto255>;

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
        let proof = VerifiableRerandomize::new::<C, _>(&pk, &r, &mut rng);
        #[cfg(feature = "elgamal3")]
        let expected = rerandomize(&c, &r);
        #[cfg(not(feature = "elgamal3"))]
        let expected = rerandomize(&c, &pk, &r);
        assert!(proof.verify::<C>(&pk));
        assert_eq!(proof.verified_reconstruct::<C>(&c, &pk), Some(expected));
    }

    #[test]
    fn vrr_tampered_proof_fails() {
        let mut rng = rand::rng();
        let (_c, pk) = setup_ct_and_pk();
        let r = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRerandomize::new::<C, _>(&pk, &r, &mut rng);
        proof.p_gy_r.c1 = proof.p_gy_r.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify::<C>(&pk));
    }
}
