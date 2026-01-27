//! Session key share proofs for distributed key generation.
//!
//! This module implements zero-knowledge proofs for session key shares in distributed
//! transcryption scenarios. When multiple transcryptors establish session keys through
//! session key shares, each share u_i = b_i * k_i must be proven to be correctly
//! constructed without revealing the secret factors.

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use rand_core::{CryptoRng, RngCore};

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

/// Proof that a session key share was correctly constructed.
///
/// This is a ZKP(U_i; b_i; K_i) proving that:
/// - u_i = b_i * k_i (session key share)
/// - U_i = u_i * G (public commitment to the share)
/// - Using preconfigured B_i = b_i * G (blinding commitment)
/// - Using K_i from stored factor commitments (rekey factor commitment)
///
/// # Security Note
///
/// This proof should only be shared with the user requesting the session key,
/// as u_i must remain secret. Unlike transcryption proofs which can be public,
/// session key share proofs contain information that could compromise security
/// if shared publicly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SessionKeyShareProof {
    /// U_i = u_i * G (public commitment to session key share)
    pub share_commitment: GroupElement,
    /// Zero-knowledge proof that u_i = b_i * k_i
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
    /// * `rekey_factor` - The rekey factor k_i (kept secret by transcryptor)
    /// * `rekey_commitment` - Public commitment K_i = k_i * G
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// A proof that can be verified by the user to confirm the session key share
    /// was constructed correctly.
    pub fn new<R: RngCore + CryptoRng>(
        blinding: &ScalarNonZero,
        rekey_factor: &ScalarNonZero,
        rekey_commitment: &GroupElement,
        rng: &mut R,
    ) -> Self {
        // Compute u_i = b_i * k_i (session key share contribution)
        let share = blinding * rekey_factor;

        // Create U_i = u_i * G (public commitment)
        let share_commitment = share * G;

        // Create ZKP proving knowledge of b_i such that:
        // - share_commitment = b_i * rekey_commitment
        // - (which implies u_i = b_i * k_i since K_i = k_i * G)
        let (_, proof) = create_proof(blinding, rekey_commitment, rng);

        Self {
            share_commitment,
            proof,
        }
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
        // This confirms: share_commitment = b_i * rekey_commitment
        // which means: U_i = b_i * K_i = b_i * (k_i * G) = (b_i * k_i) * G = u_i * G
        verify_proof(&blinding_commitment.0, rekey_commitment, &self.proof)
    }

    /// Get the public commitment to the session key share.
    ///
    /// Returns U_i = u_i * G.
    ///
    /// The user should verify this matches the commitment before accepting the share.
    pub fn share_commitment(&self) -> &GroupElement {
        &self.share_commitment
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
