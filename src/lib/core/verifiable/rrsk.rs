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
//! Unlike the standalone [`VerifiableRerandomize`](super::VerifiableRerandomize),
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
    pub rerandomize: VerifiableRerandomize,
    pub rsk: VerifiableRSK,
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

    /// The final RSK'd ciphertext.
    pub fn result(&self) -> ElGamal {
        self.rsk.result()
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        gy: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify_rrsk(
            original,
            &self.result(),
            gy,
            reshuffle_commitment,
            rekey_commitment,
        ) {
            Some(self.result())
        } else {
            None
        }
    }

    /// Full check: verify the proof and that `new` is the ciphertext it
    /// implicitly reconstructs.
    #[must_use]
    pub fn verify_rrsk(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        gy: &GroupElement,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        if !self.rerandomize.verify(gy) {
            return false;
        }
        let rerandomized = self.rerandomize.result(original);
        self.rsk
            .verify_rsk(&rerandomized, new, reshuffle_commitment, rekey_commitment)
    }
}

/// Verifiable RRSK-2: a [`VerifiableRerandomize`] composed with a
/// [`VerifiableRSK2`] on the rerandomized ciphertext.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRRSK2 {
    pub rerandomize: VerifiableRerandomize,
    pub rsk2: VerifiableRSK2,
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

    pub fn result(&self) -> ElGamal {
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
        if self.verify_rrsk2(
            original,
            &self.result(),
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

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_rrsk2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
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
        self.rsk2.verify_rsk2(
            &rerandomized,
            new,
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        )
    }
}

pub fn verifiable_rrsk<R: Rng + CryptoRng>(
    m: &ElGamal,
    gy: &GroupElement,
    r: &ScalarNonZero,
    s: &ScalarNonZero,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRRSK {
    VerifiableRRSK::new(m, gy, r, s, k, rng)
}

#[allow(clippy::too_many_arguments)]
pub fn verifiable_rrsk2<R: Rng + CryptoRng>(
    m: &ElGamal,
    gy: &GroupElement,
    r: &ScalarNonZero,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRRSK2 {
    VerifiableRRSK2::new(m, gy, r, s_from, s_to, k_from, k_to, rng)
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

    fn tamper(c: &ElGamal) -> ElGamal {
        let mut rng = rand::rng();
        let mut t = *c;
        t.gb = t.gb + GroupElement::random(&mut rng);
        t
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
        let result = run_rrsk(&c, &pk, &r, &s, &k);
        let rs = PseudonymizationFactorCommitment::new(&s);
        let rk = RekeyFactorCommitment::new(&k);
        assert_eq!(proof.result(), result);
        assert!(proof.verify_rrsk(&c, &result, &pk, &rs, &rk));
    }

    #[test]
    fn vrrsk_tampered_output_fails() {
        let mut rng = rand::rng();
        let (pk, c) = make_pk_ct();
        let r = ScalarNonZero::random(&mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRRSK::new(&c, &pk, &r, &s, &k, &mut rng);
        let real = run_rrsk(&c, &pk, &r, &s, &k);
        let bad = tamper(&real);
        let rs = PseudonymizationFactorCommitment::new(&s);
        let rk = RekeyFactorCommitment::new(&k);
        assert!(!proof.verify_rrsk(&c, &bad, &pk, &rs, &rk));
    }

    #[test]
    fn vrrsk_tampered_proof_fails() {
        let mut rng = rand::rng();
        let (pk, c) = make_pk_ct();
        let r = ScalarNonZero::random(&mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRRSK::new(&c, &pk, &r, &s, &k, &mut rng);
        let result = run_rrsk(&c, &pk, &r, &s, &k);
        let rs = PseudonymizationFactorCommitment::new(&s);
        let rk = RekeyFactorCommitment::new(&k);
        proof.rerandomize.p_gy_r.c1 = proof.rerandomize.p_gy_r.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify_rrsk(&c, &result, &pk, &rs, &rk));
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
        let result = run_rrsk2(&c, &pk, &r, &s_from, &s_to, &k_from, &k_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert_eq!(proof.result(), result);
        assert!(proof.verify_rrsk2(
            &c,
            &result,
            &pk,
            &s_from_com,
            &s_to_com,
            &k_from_com,
            &k_to_com,
        ));
    }

    #[test]
    fn vrrsk2_tampered_output_fails() {
        let mut rng = rand::rng();
        let (pk, c) = make_pk_ct();
        let r = ScalarNonZero::random(&mut rng);
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRRSK2::new(&c, &pk, &r, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let real = run_rrsk2(&c, &pk, &r, &s_from, &s_to, &k_from, &k_to);
        let bad = tamper(&real);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(!proof.verify_rrsk2(
            &c,
            &bad,
            &pk,
            &s_from_com,
            &s_to_com,
            &k_from_com,
            &k_to_com,
        ));
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
        let result = run_rrsk2(&c, &pk, &r, &s_from, &s_to, &k_from, &k_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        proof.rsk2.inner.p_gb_prime.c1 =
            proof.rsk2.inner.p_gb_prime.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify_rrsk2(
            &c,
            &result,
            &pk,
            &s_from_com,
            &s_to_com,
            &k_from_com,
            &k_to_com,
        ));
    }
}
