//! Verifiable RSK and verifiable RSK-2.
//!
//! Implements the constructions exactly as specified in the paper:
//!
//! ```text
//!  VRSK(⟨B, C, Y⟩, s, k)
//!     = ⟨ T,
//!         ZKP{S = k * T},
//!         ZKP{B' = (s·k⁻¹) * B},
//!         ZKP{C' = s * C},
//!         ZKP{Y' = k * Y} ⟩
//!     where T = (s·k⁻¹)·G.
//!
//!  VRSK2(⟨B, C, Y⟩, s_from, s_to, k_from, k_to)
//!     = ⟨ S, K,
//!         ZKP{S_to = s_from * S},
//!         ZKP{K_to = k_from * K},
//!         VRSK(⟨B, C, Y⟩, s, k) where s = s_from⁻¹·s_to, k = k_from⁻¹·k_to ⟩
//! ```
//!
//! `VerifiableRSK2` is structurally a `VerifiableRSK` (over the combined
//! scalars) plus two per-factor sub-proofs (`p_gs_to`, `p_gk_to`) tying the
//! combined commitments `S`, `K` to the published `S_from / S_to / K_from /
//! K_to` commitments. The per-factor sub-proofs depend only on the factor
//! tuple and not on any individual ciphertext.
//!
//! All ZKPs are forward (`ZKP{N = a * M}` has first component `N = a·M`).

use super::commitments::{PseudonymizationFactorCommitment, RekeyFactorCommitment};
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// VRSK
// ---------------------------------------------------------------------------

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSK {
    /// `T = (s·k⁻¹)·G`.
    pub gt: GroupElement,
    /// `ZKP{S = k * T}`: first component is `S = s·G`.
    pub p_gs: Proof,
    /// `ZKP{B' = (s·k⁻¹) * B}`: first component is `B' = (s·k⁻¹)·B`.
    pub p_gb_prime: Proof,
    /// `ZKP{C' = s * C}`: first component is `C' = s·C`.
    pub p_gc_prime: Proof,
    /// `ZKP{Y' = k * Y}`: first component is `Y' = k·Y`.
    #[cfg(feature = "elgamal3")]
    pub p_gy_prime: Proof,
}

impl VerifiableRSK {
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        s: &ScalarNonZero,
        k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let s_k_inv = s * k.invert();
        let gt = s_k_inv * G;
        let (_gk, p_gs) = create_proof(k, &gt, rng);
        let (_t_again, p_gb_prime) = create_proof(&s_k_inv, &v.gb, rng);
        let (_gs, p_gc_prime) = create_proof(s, &v.gc, rng);
        #[cfg(feature = "elgamal3")]
        let (_gk_again, p_gy_prime) = create_proof(k, &v.gy, rng);
        Self {
            gt,
            p_gs,
            p_gb_prime,
            p_gc_prime,
            #[cfg(feature = "elgamal3")]
            p_gy_prime,
        }
    }

    /// Extract the RSK'd ciphertext from the proof.
    pub fn result(&self) -> ElGamal {
        ElGamal {
            gb: *self.p_gb_prime,
            gc: *self.p_gc_prime,
            #[cfg(feature = "elgamal3")]
            gy: *self.p_gy_prime,
        }
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        reshuffle_commitments: &PseudonymizationFactorCommitment,
        rekey_commitments: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, reshuffle_commitments, rekey_commitments) {
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
    fn verify(
        &self,
        original: &ElGamal,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        let gs = reshuffle_commitment.0 .0;
        let gk = rekey_commitment.0 .0;
        if *self.p_gs != gs {
            return false;
        }
        if !verify_proof(&gk, &self.gt, &self.p_gs) {
            return false;
        }
        if !verify_proof(&self.gt, &original.gb, &self.p_gb_prime) {
            return false;
        }
        if !verify_proof(&gs, &original.gc, &self.p_gc_prime) {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if !verify_proof(&gk, &original.gy, &self.p_gy_prime) {
            return false;
        }
        true
    }

    #[must_use]
    pub fn verify_rsk(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        reshuffle_commitment: &PseudonymizationFactorCommitment,
        rekey_commitment: &RekeyFactorCommitment,
    ) -> bool {
        if !self.verify(original, reshuffle_commitment, rekey_commitment) {
            return false;
        }
        if new.gb != *self.p_gb_prime || new.gc != *self.p_gc_prime {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if new.gy != *self.p_gy_prime {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// VRSK-2
// ---------------------------------------------------------------------------

/// Verifiable RSK-2: a [`VerifiableRSK`] over the combined scalars
/// `s = s_from⁻¹·s_to`, `k = k_from⁻¹·k_to`, plus per-factor sub-proofs
/// (`p_gs_to`, `p_gk_to`) tying the combined commitments `S`, `K` to the
/// published `S_from`, `S_to`, `K_from`, `K_to` commitments.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSK2 {
    /// `S = (s_from⁻¹·s_to)·G`.
    pub gs: GroupElement,
    /// `K = (k_from⁻¹·k_to)·G`.
    pub gk: GroupElement,
    /// `ZKP{S_to = s_from * S}`: first component is `S_to = s_to·G`.
    pub p_gs_to: Proof,
    /// `ZKP{K_to = k_from * K}`: first component is `K_to = k_to·G`.
    pub p_gk_to: Proof,
    /// The per-message RSK under the combined scalars.
    pub inner: VerifiableRSK,
}

impl VerifiableRSK2 {
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let s = s_from.invert() * s_to;
        let k = k_from.invert() * k_to;
        let gs = s * G;
        let gk = k * G;
        let (_gs_from, p_gs_to) = create_proof(s_from, &gs, rng);
        let (_gk_from, p_gk_to) = create_proof(k_from, &gk, rng);
        let inner = VerifiableRSK::new(v, &s, &k, rng);
        Self {
            gs,
            gk,
            p_gs_to,
            p_gk_to,
            inner,
        }
    }

    pub fn result(&self) -> ElGamal {
        self.inner.result()
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(
            original,
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

    /// Verify the two per-factor sub-proofs once. Their combined commitments
    /// (from [`Self::combined_reshuffle_commitment`] and
    /// [`Self::combined_rekey_commitment`]) can then be reused to verify many
    /// per-message inner proofs via [`VerifiableRSK::verify_rsk`].
    #[must_use]
    pub fn verify_factor(
        &self,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        let gs_from = s_from_commitments.0 .0;
        let gs_to = s_to_commitments.0 .0;
        let gk_from = k_from_commitments.0 .0;
        let gk_to = k_to_commitments.0 .0;
        *self.p_gs_to == gs_to
            && verify_proof(&gs_from, &self.gs, &self.p_gs_to)
            && *self.p_gk_to == gk_to
            && verify_proof(&gk_from, &self.gk, &self.p_gk_to)
    }

    /// The combined reshuffle commitment `S = (s_from⁻¹·s_to)·G`.
    pub fn combined_reshuffle_commitment(&self) -> PseudonymizationFactorCommitment {
        PseudonymizationFactorCommitment(super::commitments::FactorCommitment(self.gs))
    }

    /// The combined rekey commitment `K = (k_from⁻¹·k_to)·G`.
    pub fn combined_rekey_commitment(&self) -> RekeyFactorCommitment {
        RekeyFactorCommitment(super::commitments::FactorCommitment(self.gk))
    }

    #[must_use]
    fn verify(
        &self,
        original: &ElGamal,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        self.verify_factor(
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) && self.inner.verify(
            original,
            &self.combined_reshuffle_commitment(),
            &self.combined_rekey_commitment(),
        )
    }

    #[must_use]
    pub fn verify_rsk2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        s_from_commitments: &PseudonymizationFactorCommitment,
        s_to_commitments: &PseudonymizationFactorCommitment,
        k_from_commitments: &RekeyFactorCommitment,
        k_to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        self.verify_factor(
            s_from_commitments,
            s_to_commitments,
            k_from_commitments,
            k_to_commitments,
        ) && self.inner.verify_rsk(
            original,
            new,
            &self.combined_reshuffle_commitment(),
            &self.combined_rekey_commitment(),
        )
    }
}

pub fn verifiable_rsk<R: Rng + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRSK {
    VerifiableRSK::new(m, s, k, rng)
}

pub fn verifiable_rsk2<R: Rng + CryptoRng>(
    m: &ElGamal,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRSK2 {
    VerifiableRSK2::new(m, s_from, s_to, k_from, k_to, rng)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::G;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::{rsk, rsk2};

    fn setup_ct() -> ElGamal {
        let mut rng = rand::rng();
        let sk = ScalarNonZero::random(&mut rng);
        let pk = sk * G;
        let m = GroupElement::random(&mut rng);
        encrypt(&m, &pk, &mut rng)
    }

    fn tamper(c: &ElGamal) -> ElGamal {
        let mut rng = rand::rng();
        let mut t = *c;
        t.gb = t.gb + GroupElement::random(&mut rng);
        t
    }

    // ---- VRSK ----

    #[test]
    fn vrsk_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK::new(&c, &s, &k, &mut rng);
        let result = rsk(&c, &s, &k);
        let s_com = PseudonymizationFactorCommitment::new(&s);
        let k_com = RekeyFactorCommitment::new(&k);
        assert!(proof.verify_rsk(&c, &result, &s_com, &k_com));
    }

    #[test]
    fn vrsk_tampered_output_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK::new(&c, &s, &k, &mut rng);
        let real = rsk(&c, &s, &k);
        let bad = tamper(&real);
        let s_com = PseudonymizationFactorCommitment::new(&s);
        let k_com = RekeyFactorCommitment::new(&k);
        assert!(!proof.verify_rsk(&c, &bad, &s_com, &k_com));
    }

    #[test]
    fn vrsk_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRSK::new(&c, &s, &k, &mut rng);
        let result = rsk(&c, &s, &k);
        let s_com = PseudonymizationFactorCommitment::new(&s);
        let k_com = RekeyFactorCommitment::new(&k);
        proof.p_gb_prime.c1 = proof.p_gb_prime.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify_rsk(&c, &result, &s_com, &k_com));
    }

    #[test]
    fn vrsk_wrong_s_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK::new(&c, &s, &k, &mut rng);
        let result = rsk(&c, &s, &k);
        let wrong_s = PseudonymizationFactorCommitment::new(&ScalarNonZero::random(&mut rng));
        let k_com = RekeyFactorCommitment::new(&k);
        assert!(!proof.verify_rsk(&c, &result, &wrong_s, &k_com));
    }

    // ---- VRSK2 ----

    #[test]
    fn vrsk2_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK2::new(&c, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let result = rsk2(&c, &s_from, &s_to, &k_from, &k_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(proof.verify_rsk2(&c, &result, &s_from_com, &s_to_com, &k_from_com, &k_to_com));
    }

    #[test]
    fn vrsk2_tampered_output_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK2::new(&c, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let real = rsk2(&c, &s_from, &s_to, &k_from, &k_to);
        let bad = tamper(&real);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(!proof.verify_rsk2(&c, &bad, &s_from_com, &s_to_com, &k_from_com, &k_to_com));
    }

    #[test]
    fn vrsk2_wrong_to_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRSK2::new(&c, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let result = rsk2(&c, &s_from, &s_to, &k_from, &k_to);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_other = RekeyFactorCommitment::new(&ScalarNonZero::random(&mut rng));
        assert!(!proof.verify_rsk2(
            &c,
            &result,
            &s_from_com,
            &s_to_com,
            &k_from_com,
            &k_to_other
        ));
    }

    #[test]
    fn vrsk2_factor_then_many_inner() {
        let mut rng = rand::rng();
        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let c1 = setup_ct();
        let c2 = setup_ct();
        let vrsk2 = VerifiableRSK2::new(&c1, &s_from, &s_to, &k_from, &k_to, &mut rng);
        let s_from_com = PseudonymizationFactorCommitment::new(&s_from);
        let s_to_com = PseudonymizationFactorCommitment::new(&s_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(vrsk2.verify_factor(&s_from_com, &s_to_com, &k_from_com, &k_to_com));
        let s = s_from.invert() * s_to;
        let k = k_from.invert() * k_to;
        let inner2 = VerifiableRSK::new(&c2, &s, &k, &mut rng);
        let result2 = rsk2(&c2, &s_from, &s_to, &k_from, &k_to);
        assert!(inner2.verify_rsk(
            &c2,
            &result2,
            &vrsk2.combined_reshuffle_commitment(),
            &vrsk2.combined_rekey_commitment(),
        ));
    }
}
