//! Session-key-share proofs for the blinded-product key construction.
//!
//! libpep distributes session keys using a **blinded-product** construction,
//! NOT a Distributed Key Generation (DKG) / Verifiable Secret Sharing (VSS)
//! scheme. The construction works as follows:
//!
//! - Each transcryptor `i` holds a secret blinding scalar `b_i`.
//! - At setup, a dealer computes the blinded global secret key
//!   `sk' = sk · ∏ b_i⁻¹` and publishes it together with the global public
//!   key. Each transcryptor receives its own `b_i` over a secure channel.
//! - To derive a session key for a context, each transcryptor computes its
//!   own session-key share `u_i = b_i · k_i`, where
//!   `k_i = derive(context)` is a publicly-recomputable rekey factor for
//!   that context. The user multiplies `sk'` by all shares `u_i` to obtain
//!   the session secret key:
//!   `sk_session = sk' · ∏ u_i = sk · ∏ b_i⁻¹ · ∏ (b_i · k_i) = sk · ∏ k_i`.
//!
//! This module's [`SessionKeyShareProof`] proves, in zero knowledge, that an
//! individual transcryptor `i` correctly computed its share `u_i = b_i · k_i`
//! using the blinding scalar `b_i` previously committed to as `B_i = b_i · G`
//! and the publicly-recomputable rekey factor commitment `K_i = k_i · G`.
//!
//! # Security model
//!
//! What this proof **does** guarantee:
//! - For each transcryptor `i`, the published share commitment
//!   `U_i = u_i · G` is exactly `b_i · k_i · G`, where `b_i` matches the
//!   pre-configured blinding commitment `B_i = b_i · G` and `k_i` is the
//!   rekey factor derived from the (known, deterministic) context.
//!
//! What this proof **does NOT** guarantee:
//! - That at setup the dealer actually used the same `b_i` in computing
//!   `sk' = sk · ∏ b_i⁻¹` as the `b_i` that was shipped to transcryptor `i`.
//!   There is no commitment phase, no broadcast, and no proof tying the
//!   blinded global secret key back to the individual `B_i`. A malicious
//!   dealer could in principle use a different set of blinding scalars in
//!   the product than the ones it distributed. **The dealer is therefore a
//!   trusted party at setup time.** Once setup is complete (and the dealer
//!   is gone), the per-share proofs in this module guarantee correctness of
//!   each transcryptor's contribution at session-derivation time.

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, Rng};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Commitment to a blinding factor b_i.
///
/// This is B_i = b_i * G, a public commitment to the secret blinding value.
/// The blinding commitment is preconfigured and shared with verifiers to enable
/// verification of session key share proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlindingCommitment(pub GroupElement);

impl BlindingCommitment {
    /// Create a new blinding commitment from a blinding factor.
    ///
    /// Computes B_i = b_i * G.
    pub fn new(blinding: &ScalarNonZero) -> Self {
        Self(blinding * G)
    }

    /// Get the commitment value.
    pub fn value(&self) -> &GroupElement {
        &self.0
    }
}

/// Proof that a session-key share was correctly constructed.
///
/// This is a ZKP(U_i; b_i; K_i) proving that:
/// - u_i = b_i * k_i (session-key share scalar)
/// - U_i = u_i * G (public commitment to the share)
/// - Using preconfigured B_i = b_i * G (blinding commitment)
/// - Using K_i from stored factor commitments (rekey factor commitment)
///
/// # Security Note
///
/// The proof reveals `U_i = u_i · G` (the public commitment to the share)
/// but the underlying scalar `u_i` MUST remain secret to the transcryptor
/// and the user requesting the session key. Anyone holding all `u_i` along
/// with the blinded global secret key `sk'` can reconstruct `sk_session`.
/// The proof itself can be transmitted over the same channel as the share
/// scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SessionKeyShareProof {
    /// Zero-knowledge proof that u_i = b_i * k_i.
    ///
    /// The proof's `n` field equals `U_i = u_i · G`, the public commitment
    /// to the session-key share. It is checked against `b_i · K_i` by
    /// [`SessionKeyShareProof::verify`].
    pub proof: Proof,
}

impl SessionKeyShareProof {
    /// Create a session key share proof.
    ///
    /// Proves that the session key share u_i was correctly constructed as u_i = b_i * k_i.
    ///
    /// # Arguments
    ///
    /// * `blinding` - The blinding factor b_i (kept secret by transcryptor)
    /// * `_rekey_factor` - Currently unused (kept for API stability — the proof
    ///   is constructed against `rekey_commitment = k_i · G`, so the scalar
    ///   `k_i` itself is not needed).
    /// * `rekey_commitment` - Public commitment K_i = k_i * G
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// A proof that can be verified by the user to confirm the session key share
    /// was constructed correctly.
    pub fn new<R: Rng + CryptoRng>(
        blinding: &ScalarNonZero,
        _rekey_factor: &ScalarNonZero,
        rekey_commitment: &GroupElement,
        rng: &mut R,
    ) -> Self {
        // Create ZKP proving knowledge of b_i such that:
        // - proof.n = U_i = b_i * rekey_commitment = b_i * k_i * G = u_i * G
        // - (which implies u_i = b_i * k_i since K_i = k_i * G)
        let (_, proof) = create_proof(blinding, rekey_commitment, rng);

        Self { proof }
    }

    /// Verify a session key share proof.
    ///
    /// Checks that:
    /// 1. The proof is valid (proves knowledge of b_i)
    /// 2. U_i = b_i * K_i (using the blinding commitment)
    ///
    /// # Arguments
    ///
    /// * `blinding_commitment` - B_i = b_i * G (preconfigured commitment)
    /// * `rekey_commitment` - K_i = k_i * G (from factor commitments)
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(
        &self,
        blinding_commitment: &BlindingCommitment,
        rekey_commitment: &GroupElement,
    ) -> bool {
        // Verify the ZKP
        // This confirms: proof.n = b_i * rekey_commitment
        // which means: U_i = b_i * K_i = b_i * (k_i * G) = (b_i * k_i) * G = u_i * G
        verify_proof(&blinding_commitment.0, rekey_commitment, &self.proof)
    }

    /// Get the public commitment to the session key share.
    ///
    /// Returns U_i = u_i * G. This is simply `self.proof.n`: in the honest
    /// construction the proof's `n` value IS the share commitment.
    ///
    /// The user should verify the proof before relying on this value.
    pub fn share_commitment(&self) -> &GroupElement {
        &self.proof.n
    }
}

/// Bundle of blinding commitments for a transcryptor.
///
/// Contains commitments B_i = b_i * G for both pseudonym and attribute blinding factors.
/// These are preconfigured and shared with users to enable verification of session key shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlindingCommitments {
    /// Blinding commitment for pseudonym session keys
    pub pseudonym: BlindingCommitment,
    /// Blinding commitment for attribute session keys
    pub attribute: BlindingCommitment,
}

impl BlindingCommitments {
    /// Create blinding commitments from blinding factors.
    pub fn new(pseudonym_blinding: &ScalarNonZero, attribute_blinding: &ScalarNonZero) -> Self {
        Self {
            pseudonym: BlindingCommitment::new(pseudonym_blinding),
            attribute: BlindingCommitment::new(attribute_blinding),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blinding_commitment() {
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let commitment = BlindingCommitment::new(&blinding);

        assert_eq!(*commitment.value(), blinding * G);
    }

    #[test]
    fn test_session_key_share_proof_valid() {
        let mut rng = rand::rng();

        // Create secret factors
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        // Create commitments
        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;

        // Create proof
        let proof =
            SessionKeyShareProof::new(&blinding, &rekey_factor, &rekey_commitment, &mut rng);

        // Verify proof
        assert!(proof.verify(&blinding_commitment, &rekey_commitment));

        // Verify U_i = (b_i * k_i) * G
        let expected_share_commitment = (blinding * rekey_factor) * G;
        assert_eq!(*proof.share_commitment(), expected_share_commitment);
    }

    #[test]
    fn test_share_commitment_equals_proof_n() {
        // Regression test for the removed redundant `share_commitment` field.
        // `share_commitment()` MUST return `&self.proof.n` so a malicious
        // prover cannot publish a different value via the public getter than
        // what the proof actually proves.
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);
        let rekey_commitment = rekey_factor * G;

        let proof =
            SessionKeyShareProof::new(&blinding, &rekey_factor, &rekey_commitment, &mut rng);

        assert_eq!(proof.share_commitment(), &proof.proof.n);
    }

    #[test]
    fn test_session_key_share_proof_wrong_blinding() {
        let mut rng = rand::rng();

        let blinding = ScalarNonZero::random(&mut rng);
        let wrong_blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let wrong_commitment = BlindingCommitment::new(&wrong_blinding);
        let rekey_commitment = rekey_factor * G;

        let proof =
            SessionKeyShareProof::new(&blinding, &rekey_factor, &rekey_commitment, &mut rng);

        // Should fail with wrong blinding commitment
        assert!(!proof.verify(&wrong_commitment, &rekey_commitment));
    }

    #[test]
    fn test_session_key_share_proof_wrong_rekey() {
        let mut rng = rand::rng();

        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);
        let wrong_rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let wrong_rekey_commitment = wrong_rekey_factor * G;

        let proof =
            SessionKeyShareProof::new(&blinding, &rekey_factor, &rekey_commitment, &mut rng);

        // Should fail with wrong rekey commitment
        assert!(!proof.verify(&blinding_commitment, &wrong_rekey_commitment));
    }
}
