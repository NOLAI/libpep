//! Verifiable rekey and verifiable rekey-2.
//!
//! Implements the [`VerifiableRekey`] and [`VerifiableRekey2`] constructions
//! exactly as specified in the paper:
//!
//! ```text
//!  VRekey(⟨B, C, Y⟩, k)  = ⟨ B', ZKP{B = k * B'}, ZKP{Y' = k * Y} ⟩
//!  VRekey2(⟨B, C, Y⟩, k_from, k_to)
//!     = ⟨ K, ZKP{K_to = k_from * K}, VRekey(⟨B, C, Y⟩, k_from⁻¹·k_to) ⟩
//! ```
//!
//! `VerifiableRekey2` is structurally a `VerifiableRekey` (over the combined
//! scalar `k = k_from⁻¹·k_to`) plus the per-factor sub-proof tying `K` to the
//! transcryptor's published `K_from`, `K_to` commitments. The per-factor
//! sub-proof depends only on `(k_from, k_to)` and not on any individual
//! ciphertext — so when transcrypting many ciphertexts under the same
//! transition, the outer `VerifiableRekey2` can be built once and the inner
//! [`VerifiableRekey`] re-generated cheaply per ciphertext.
//!
//! Each proof is a *forward* discrete-log equality proof: the first component
//! of a `ZKP{N = a * M}` equals `a·M`, and the proof is verified against the
//! forward commitment `A = a·G`.

use super::commitments::RekeyFactorCommitment;
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Verifiable rekey: `⟨B', ZKP{B = k * B'}, ZKP{Y' = k * Y}⟩`.
///
/// * `gb_prime` is the new first component `B' = k⁻¹·B`.
/// * `p_gb` is `ZKP{B = k * B'}`: its first component equals `B`, so the proof
///   shows that the prover knows `k` with `B = k·B'`, verified against the
///   factor commitment `K = k·G`.
/// * `p_gy_prime` (elgamal3) is `ZKP{Y' = k * Y}`: its first component equals
///   `Y' = k·Y`, verified against `K`.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRekey {
    pub gb_prime: GroupElement,
    pub p_gb: Proof,
    #[cfg(feature = "elgamal3")]
    pub p_gy_prime: Proof,
}

impl VerifiableRekey {
    pub fn new<R: Rng + CryptoRng>(v: &ElGamal, k: &ScalarNonZero, rng: &mut R) -> Self {
        let gb_prime = k.invert() * v.gb;
        let (_gk, p_gb) = create_proof(k, &gb_prime, rng);
        #[cfg(feature = "elgamal3")]
        let (_gk_again, p_gy_prime) = create_proof(k, &v.gy, rng);
        Self {
            gb_prime,
            p_gb,
            #[cfg(feature = "elgamal3")]
            p_gy_prime,
        }
    }

    pub fn result(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: self.gb_prime,
            gc: original.gc,
            #[cfg(feature = "elgamal3")]
            gy: *self.p_gy_prime,
        }
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        commitments: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, commitments) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.result(original)
    }

    #[must_use]
    fn verify(&self, original: &ElGamal, commitment: &RekeyFactorCommitment) -> bool {
        let gk = commitment.0 .0;
        if *self.p_gb != original.gb {
            return false;
        }
        if !verify_proof(&gk, &self.gb_prime, &self.p_gb) {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if !verify_proof(&gk, &original.gy, &self.p_gy_prime) {
            return false;
        }
        true
    }

    /// Full check: verify the proof and that `new` is the ciphertext it
    /// implicitly reconstructs.
    #[must_use]
    pub fn verify_rekey(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        commitment: &RekeyFactorCommitment,
    ) -> bool {
        if !self.verify(original, commitment) {
            return false;
        }
        if new.gb != self.gb_prime || new.gc != original.gc {
            return false;
        }
        #[cfg(feature = "elgamal3")]
        if new.gy != *self.p_gy_prime {
            return false;
        }
        true
    }
}

/// Verifiable rekey-2: a [`VerifiableRekey`] over the combined scalar
/// `k = k_from⁻¹·k_to`, plus the per-factor sub-proof tying `K = k·G` to the
/// published `K_from`, `K_to` commitments.
///
/// `gk` and `p_gk_to` depend only on `(k_from, k_to)` and not on any
/// individual ciphertext. When transcrypting many ciphertexts under the same
/// transition, build a single `VerifiableRekey2` once and re-use the inner
/// [`VerifiableRekey`] / combined commitment for cheap per-ciphertext proofs.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRekey2 {
    /// `K = (k_from⁻¹ · k_to) · G`.
    pub gk: GroupElement,
    /// `ZKP{K_to = k_from * K}`: first component equals `K_to = k_to·G`.
    pub p_gk_to: Proof,
    /// The per-message rekey under the combined scalar.
    pub inner: VerifiableRekey,
}

impl VerifiableRekey2 {
    pub fn new<R: Rng + CryptoRng>(
        v: &ElGamal,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let k = k_from.invert() * k_to;
        let gk = k * G;
        let (_gk_from, p_gk_to) = create_proof(k_from, &gk, rng);
        let inner = VerifiableRekey::new(v, &k, rng);
        Self { gk, p_gk_to, inner }
    }

    pub fn result(&self, original: &ElGamal) -> ElGamal {
        self.inner.result(original)
    }

    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        from_commitments: &RekeyFactorCommitment,
        to_commitments: &RekeyFactorCommitment,
    ) -> Option<ElGamal> {
        if self.verify(original, from_commitments, to_commitments) {
            Some(self.result(original))
        } else {
            None
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.result(original)
    }

    /// Verify the per-factor sub-proof (`p_gk_to`) once. Returns the combined
    /// commitment `K = gk` on success, suitable for verifying many per-message
    /// inner proofs against via [`VerifiableRekey::verify_rekey`] with the
    /// commitment from [`Self::combined_commitment`].
    #[must_use]
    pub fn verify_factor(
        &self,
        from_commitments: &RekeyFactorCommitment,
        to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        let gk_from = from_commitments.0 .0;
        let gk_to = to_commitments.0 .0;
        *self.p_gk_to == gk_to && verify_proof(&gk_from, &self.gk, &self.p_gk_to)
    }

    /// The combined commitment `K = (k_from⁻¹·k_to)·G`, suitable for
    /// verifying many per-message [`VerifiableRekey`] proofs against once the
    /// outer `VerifiableRekey2` has been validated with [`Self::verify_factor`].
    pub fn combined_commitment(&self) -> RekeyFactorCommitment {
        RekeyFactorCommitment(super::commitments::FactorCommitment(self.gk))
    }

    #[must_use]
    fn verify(
        &self,
        original: &ElGamal,
        from_commitments: &RekeyFactorCommitment,
        to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        self.verify_factor(from_commitments, to_commitments)
            && self.inner.verify(original, &self.combined_commitment())
    }

    #[must_use]
    pub fn verify_rekey2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        from_commitments: &RekeyFactorCommitment,
        to_commitments: &RekeyFactorCommitment,
    ) -> bool {
        self.verify_factor(from_commitments, to_commitments)
            && self
                .inner
                .verify_rekey(original, new, &self.combined_commitment())
    }
}

pub fn verifiable_rekey<R: Rng + CryptoRng>(
    m: &ElGamal,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekey {
    VerifiableRekey::new(m, k, rng)
}

pub fn verifiable_rekey2<R: Rng + CryptoRng>(
    m: &ElGamal,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekey2 {
    VerifiableRekey2::new(m, k_from, k_to, rng)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::G;
    use crate::core::elgamal::encrypt;
    use crate::core::primitives::{rekey, rekey2};

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

    // ---- VRK ----

    #[test]
    fn vrk_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRekey::new(&c, &k, &mut rng);
        let result = rekey(&c, &k);
        let commitments = RekeyFactorCommitment::new(&k);
        assert!(proof.verify_rekey(&c, &result, &commitments));
    }

    #[test]
    fn vrk_tampered_output_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRekey::new(&c, &k, &mut rng);
        let real = rekey(&c, &k);
        let bad = tamper(&real);
        let commitments = RekeyFactorCommitment::new(&k);
        assert!(!proof.verify_rekey(&c, &bad, &commitments));
    }

    #[test]
    fn vrk_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRekey::new(&c, &k, &mut rng);
        let result = rekey(&c, &k);
        let commitments = RekeyFactorCommitment::new(&k);
        proof.p_gb.c1 = proof.p_gb.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify_rekey(&c, &result, &commitments));
    }

    #[test]
    fn vrk_wrong_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k = ScalarNonZero::random(&mut rng);
        let k_other = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRekey::new(&c, &k, &mut rng);
        let result = rekey(&c, &k);
        let wrong = RekeyFactorCommitment::new(&k_other);
        assert!(!proof.verify_rekey(&c, &result, &wrong));
    }

    // ---- VRK2 ----

    #[test]
    fn vrk2_honest_verifies() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRekey2::new(&c, &k_from, &k_to, &mut rng);
        let result = rekey2(&c, &k_from, &k_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(proof.verify_rekey2(&c, &result, &k_from_com, &k_to_com));
    }

    #[test]
    fn vrk2_tampered_output_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRekey2::new(&c, &k_from, &k_to, &mut rng);
        let real = rekey2(&c, &k_from, &k_to);
        let bad = tamper(&real);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        assert!(!proof.verify_rekey2(&c, &bad, &k_from_com, &k_to_com));
    }

    #[test]
    fn vrk2_tampered_proof_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let mut proof = VerifiableRekey2::new(&c, &k_from, &k_to, &mut rng);
        let result = rekey2(&c, &k_from, &k_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        proof.inner.p_gb.c1 = proof.inner.p_gb.c1 + GroupElement::random(&mut rng);
        assert!(!proof.verify_rekey2(&c, &result, &k_from_com, &k_to_com));
    }

    #[test]
    fn vrk2_wrong_to_commitment_fails() {
        let mut rng = rand::rng();
        let c = setup_ct();
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let proof = VerifiableRekey2::new(&c, &k_from, &k_to, &mut rng);
        let result = rekey2(&c, &k_from, &k_to);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_other = RekeyFactorCommitment::new(&ScalarNonZero::random(&mut rng));
        assert!(!proof.verify_rekey2(&c, &result, &k_from_com, &k_to_other));
    }

    // ---- VRK2 reused as per-factor block ----

    #[test]
    fn vrk2_factor_then_many_inner() {
        let mut rng = rand::rng();
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);
        let c1 = setup_ct();
        let c2 = setup_ct();
        let vrk2 = VerifiableRekey2::new(&c1, &k_from, &k_to, &mut rng);
        let k_from_com = RekeyFactorCommitment::new(&k_from);
        let k_to_com = RekeyFactorCommitment::new(&k_to);
        // Verify the per-factor block once.
        assert!(vrk2.verify_factor(&k_from_com, &k_to_com));
        // Then cheap per-message proofs for additional ciphertexts.
        let k = k_from.invert() * k_to;
        let inner2 = VerifiableRekey::new(&c2, &k, &mut rng);
        let result2 = rekey2(&c2, &k_from, &k_to);
        assert!(inner2.verify_rekey(&c2, &result2, &vrk2.combined_commitment()));
    }
}
