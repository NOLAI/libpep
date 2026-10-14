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

//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`BlindingCommitment`](generic::BlindingCommitment) over ristretto255.
pub type BlindingCommitment = generic::BlindingCommitment<Ristretto255>;
/// The [`SessionKeyShareProof`](generic::SessionKeyShareProof) over ristretto255.
pub type SessionKeyShareProof = generic::SessionKeyShareProof<Ristretto255>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::keys::distribution::shares::SessionKeyShare;
    use crate::keys::distribution::shares::{AttributeSessionKeyShare, PseudonymSessionKeyShare};

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
        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

        // Verify proof
        assert!(proof.verify(&blinding_commitment, &rekey_commitment));

        // Verify U_i = (b_i * k_i) * G
        let expected_share_commitment = (blinding * rekey_factor) * G;
        assert_eq!(*proof.share_commitment(), expected_share_commitment);
    }

    #[test]
    fn test_share_commitment_equals_proof_n() {
        // Regression test for the removed redundant `share_commitment` field.
        // `share_commitment()` MUST return the inner proof's `n` so a
        // malicious prover cannot publish a different value via the public
        // getter than what the proof actually proves.
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);
        let rekey_commitment = rekey_factor * G;

        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

        assert_eq!(proof.share_commitment(), proof.proof().n());
    }

    #[test]
    fn verify_share_accepts_the_matching_share() {
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

        // The honest share: u_i = b_i * k_i.
        let share = PseudonymSessionKeyShare::from_scalar(blinding * rekey_factor);

        assert!(proof.verify_share(&share, &blinding_commitment, &rekey_commitment));
    }

    #[test]
    fn verify_share_rejects_a_share_that_does_not_match_a_valid_proof() {
        // The proof here is entirely valid: it verifies against the right
        // commitments. Only the scalar handed over alongside it is wrong,
        // which is exactly the attack `verify` alone cannot catch.
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

        // The proof itself is sound...
        assert!(proof.verify(&blinding_commitment, &rekey_commitment));

        // ...but the share does not correspond to it.
        let wrong_share = PseudonymSessionKeyShare::from_scalar(ScalarNonZero::random(&mut rng));

        assert!(!proof.matches_share(&wrong_share));
        assert!(!proof.verify_share(&wrong_share, &blinding_commitment, &rekey_commitment));
    }

    #[test]
    fn verify_share_rejects_a_matching_share_under_a_bad_proof() {
        // Mirror image: the share matches `U_i`, but the proof does not verify
        // against the configured blinding commitment.
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let wrong_blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let wrong_commitment = BlindingCommitment::new(&wrong_blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

        let share = PseudonymSessionKeyShare::from_scalar(blinding * rekey_factor);

        assert!(proof.matches_share(&share));
        assert!(!proof.verify_share(&share, &wrong_commitment, &rekey_commitment));
    }

    #[test]
    fn verify_share_works_for_attribute_shares_too() {
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

        let share = AttributeSessionKeyShare::from_scalar(blinding * rekey_factor);
        let wrong = AttributeSessionKeyShare::from_scalar(ScalarNonZero::random(&mut rng));

        assert!(proof.verify_share(&share, &blinding_commitment, &rekey_commitment));
        assert!(!proof.verify_share(&wrong, &blinding_commitment, &rekey_commitment));
    }

    #[test]
    fn test_session_key_share_proof_wrong_blinding() {
        let mut rng = rand::rng();

        let blinding = ScalarNonZero::random(&mut rng);
        let wrong_blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let wrong_commitment = BlindingCommitment::new(&wrong_blinding);
        let rekey_commitment = rekey_factor * G;

        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

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

        let proof = SessionKeyShareProof::new(&blinding, &rekey_commitment, &mut rng);

        // Should fail with wrong rekey commitment
        assert!(!proof.verify(&blinding_commitment, &wrong_rekey_commitment));
    }
}
