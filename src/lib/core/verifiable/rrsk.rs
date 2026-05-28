//! Verifiable RRSK and verifiable RRSK-2.
//!
//! Defined as the sequential composition of a verifiable rerandomize and a
//! verifiable RSK / RSK-2:
//!
//! ```text
//!  VRRSK(⟨B, C, Y⟩, r, s, k)
//!     = ⟨ VRerandomize(⟨B, C, Y⟩, r), VRSK(⟨B_r, C_r, Y⟩, s, k) ⟩
//!  VRRSK2(⟨B, C, Y⟩, r, s_from, s_to, k_from, k_to)
//!     = ⟨ VRerandomize(⟨B, C, Y⟩, r),
//!         VRSK2(⟨B_r, C_r, Y⟩, s_from, s_to, k_from, k_to) ⟩
//! ```
//!
//! where `B_r = R + B`, `C_r = Y_r + C` are the rerandomized first and second
//! components. The verifier reconstructs them from the rerandomize step and
//! then verifies the VRSK / VRSK2 proof against them.
//!
//! Unlike the standalone [`VerifiableRerandomize`],
//! which is only available with `insecure` because the rerandomization can be
//! applied unbounded, VRRSK and VRRSK-2 *do* tie the rerandomization to a
//! specific `(s, k)` (or `(s_from, s_to, k_from, k_to)`) tuple via the
//! subsequent RSK proof and so are available in the default feature set.

use super::commitments::{PseudonymizationFactorCommitment, RekeyFactorCommitment};
use super::rerandomize::VerifiableRerandomize;
use super::rsk::{VerifiableRSK, VerifiableRSK2};
use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Verifiable RRSK: a [`VerifiableRerandomize`] composed with a
/// [`VerifiableRSK`] on the rerandomized ciphertext.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRRSK {
    pub(crate) rerandomize: VerifiableRerandomize,
    pub(crate) rsk: VerifiableRSK,
}

impl VerifiableRRSK {
    /// The rerandomize sub-proof.
    pub fn rerandomize(&self) -> &VerifiableRerandomize {
        &self.rerandomize
    }
    /// The RSK sub-proof.
    pub fn rsk(&self) -> &VerifiableRSK {
        &self.rsk
    }
}

impl VerifiableRRSK {
    /// Build a VRRSK proof.
    ///
    /// `gy` is the recipient public key against which the ciphertext was
    /// encrypted (in `elgamal3` mode this equals `v.gy`; in the default mode
    /// the caller supplies it explicitly).
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        gy: &GroupElement,
        r: &ScalarNonZero,
        s: &ScalarNonZero,
        k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let rerandomize = VerifiableRerandomize::new(gy, r, rng);
        let rerandomized = rerandomize.result(v);
        let rsk = VerifiableRSK::new(&rerandomized, s, k, rng);
        Self { rerandomize, rsk }
    }

    /// Reconstruct the RRSK'd ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only — public callers should
    /// use [`verified_reconstruct`](Self::verified_reconstruct).
    pub(crate) fn result(&self) -> ElGamal {
        self.rsk.result()
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        gy: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, gy, reshuffle_commitment, rekey_commitment) {
            Some(self.result())
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.result()
    }

    /// Verify the proof against `original` and `gy`.
    #[must_use]
    pub fn verify(
        &self,
        original: &ElGamal,
        gy: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        if !self.rerandomize.verify(gy) {
            return false;
        }
        let rerandomized = self.rerandomize.result(original);
        self.rsk
            .verify(&rerandomized, reshuffle_commitment, rekey_commitment)
    }
}

/// Verifiable RRSK-2: a [`VerifiableRerandomize`] composed with a
/// [`VerifiableRSK2`] on the rerandomized ciphertext.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRRSK2 {
    pub(crate) rerandomize: VerifiableRerandomize,
    pub(crate) rsk2: VerifiableRSK2,
}

impl VerifiableRRSK2 {
    /// The rerandomize sub-proof.
    pub fn rerandomize(&self) -> &VerifiableRerandomize {
        &self.rerandomize
    }
    /// The RSK-2 sub-proof.
    pub fn rsk2(&self) -> &VerifiableRSK2 {
        &self.rsk2
    }
}

impl VerifiableRRSK2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        gy: &GroupElement,
        r: &ScalarNonZero,
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let rerandomize = VerifiableRerandomize::new(gy, r, rng);
        let rerandomized = rerandomize.result(v);
        let rsk2 = VerifiableRSK2::new(&rerandomized, s_from, s_to, k_from, k_to, rng);
        Self { rerandomize, rsk2 }
    }

    /// Reconstruct the RRSK-2'd ciphertext from this proof, **without
    /// verifying** it. Internal prover-side use only.
    pub(crate) fn result(&self) -> ElGamal {
        self.rsk2.result()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        gy: &GroupElement,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(
            original,
            gy,
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) {
            Some(self.result())
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.result()
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        original: &ElGamal,
        gy: &GroupElement,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        if !self.rerandomize.verify(gy) {
            return false;
        }
        let rerandomized = self.rerandomize.result(original);
        self.rsk2.verify(
            &rerandomized,
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::G;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::{rrsk, rrsk2};

    fn make_pk_ct() -> (GroupElement, ElGamal) {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        let c = encrypt(&m, &pk, &mut rng);
        (pk, c)
    }

    fn run_rrsk(
        c: &ElGamal,
        gy: &GroupElement,
        r: &ScalarNonZero,
        s: &ScalarNonZero,
        k: &ScalarNonZero,
    ) -> ElGamal {
        #[cfg(feature = "elgamal3")]
        {
            let _ = gy;
            rrsk(c, r, s, k)
        }
        #[cfg(not(feature = "elgamal3"))]
        {
            rrsk(c, gy, r, s, k)
        }
    }

    fn run_rrsk2(
        c: &ElGamal,
        gy: &GroupElement,
        r: &ScalarNonZero,
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
    ) -> ElGamal {
        #[cfg(feature = "elgamal3")]
        {
            let _ = gy;
            rrsk2(c, r, s_from, s_to, k_from, k_to)
        }
        #[cfg(not(feature = "elgamal3"))]
        {
            rrsk2(c, gy, r, s_from, s_to, k_from, k_to)
        }
    }

    #[test]
    fn vrrsk_honest_verifies() {
        let mut rng = rand::rng();
        let (pk, c) = make_pk_ct();
        let r = ScalarNonZero::random(&mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRRSK::new(&c, &pk, &r, &s, &k, &mut rng);
        let expected = run_rrsk(&c, &pk, &r, &s, &k);
        let rs = PseudonymizationFactorCommitment::new(&s);
        let rk = RekeyFactorCommitment::new(&k);
        assert_eq!(proof.result(), expected);
        assert!(proof.verify(&c, &pk, &rs, &rk));
        assert_eq!(
            proof.verified_reconstruct(&c, &pk, &rs, &rk),
            Some(expected)
        );
    }

    #[test]
    fn vrrsk_tampered_proof_fails() {
        let mut rng = rand::rng();
        let (pk, c) = make_pk_ct();
        let r = ScalarNonZero::random(&mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRRSK::new(&c, &pk, &r, &s, &k, &mut rng);
        let rs = PseudonymizationFactorCommitment::new(&s);
        let rk = RekeyFactorCommitment::new(&k);
        proof.rerandomize.p_gy_r.c1 = proof.rerandomize.p_gy_r.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify(&c, &pk, &rs, &rk));
    }

    #[test]
    fn vrrsk2_honest_verifies() {
        let mut rng = rand::rng();
        let (pk, c) = make_pk_ct();
        let r = ScalarNonZero::random(&mut rng);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRRSK2::new(&c, &pk, &r, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let expected = run_rrsk2(&c, &pk, &r, &s_from, &s_to, &k_from, &k_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert_eq!(proof.result(), expected);
        assert!(proof.verify(&c, &pk, &s_from_com, &s_to_com, &k_from_com, &k_to_com));
        assert_eq!(
            proof.verified_reconstruct(&c, &pk, &s_from_com, &s_to_com, &k_from_com, &k_to_com),
            Some(expected)
        );
    }

    #[test]
    fn vrrsk2_tampered_proof_fails() {
        let mut rng = rand::rng();
        let (pk, c) = make_pk_ct();
        let r = ScalarNonZero::random(&mut rng);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRRSK2::new(&c, &pk, &r, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        proof.rsk2.inner.inner.p_gb_prime.c1 =
            proof.rsk2.inner.inner.p_gb_prime.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify(&c, &pk, &s_from_com, &s_to_com, &k_from_com, &k_to_com));
    }
}
