//! Session-key-share proofs generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::zkps::generic::{create_proof, verify_proof, Proof};
use crate::keys::distribution::shares::SessionKeyShare;
use rand_core::{CryptoRng, Rng};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Commitment to a blinding factor b_i.
///
/// This is B_i = b_i * G, a public commitment to the secret blinding value.
/// The blinding commitment is preconfigured and shared with verifiers to enable
/// verification of session key share proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct BlindingCommitment<G: Group>(pub G::Element);

impl<G: Group> BlindingCommitment<G> {
    /// Create a new blinding commitment from a blinding factor.
    ///
    /// Computes B_i = b_i * G.
    pub fn new(blinding: &G::Scalar) -> Self {
        Self(*blinding * G::generator())
    }

    /// Get the commitment value.
    pub fn value(&self) -> &G::Element {
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct SessionKeyShareProof<G: Group> {
    /// Zero-knowledge proof that u_i = b_i * k_i.
    ///
    /// The proof's `n` field equals `U_i = u_i · G`, the public commitment
    /// to the session-key share. It is checked against `b_i · K_i` by
    /// [`SessionKeyShareProof::verify`].
    ///
    /// Kept private so that a verifier handed a `SessionKeyShareProof` cannot
    /// have its inner proof swapped after the fact; read-only access is via
    /// [`SessionKeyShareProof::proof`] and [`SessionKeyShareProof::share_commitment`].
    proof: Proof<G>,
}

impl<G: Group> SessionKeyShareProof<G> {
    /// Create a session key share proof.
    ///
    /// Proves that the session key share u_i was correctly constructed as u_i = b_i * k_i.
    ///
    /// # Arguments
    ///
    /// * `blinding` - The blinding factor b_i (kept secret by transcryptor)
    /// * `rekey_commitment` - Public commitment K_i = k_i * G
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// A proof that can be verified by the user to confirm the session key share
    /// was constructed correctly.
    pub fn new<R: Rng + CryptoRng>(
        blinding: &G::Scalar,
        rekey_commitment: &G::Element,
        rng: &mut R,
    ) -> Self {
        // Create ZKP proving knowledge of b_i such that:
        // - proof.n = U_i = b_i * rekey_commitment = b_i * k_i * G = u_i * G
        // - (which implies u_i = b_i * k_i since K_i = k_i * G)
        let (_, proof) = create_proof::<G, R>(blinding, rekey_commitment, rng);

        Self { proof }
    }

    /// The underlying zero-knowledge proof.
    pub fn proof(&self) -> &Proof<G> {
        &self.proof
    }

    /// Verify the proof *and* bind it to the share scalar actually received.
    ///
    /// This is the check a user of a session key share must perform. It
    /// establishes both halves of the paper's requirement:
    ///
    /// 1. the ZKP is valid against the preconfigured `B_i = b_i · G` and the
    ///    rekey commitment `K_i`, so the proven `U_i` equals `b_i · K_i`
    ///    ([`SessionKeyShareProof::verify`]); and
    /// 2. `U_i == u_i · G` for the share scalar `u_i` that was received, so the
    ///    scalar the user is about to fold into its session key is the one the
    ///    proof is about.
    ///
    /// Without the second check a transcryptor can hand over a perfectly valid
    /// proof together with an unrelated scalar: the proof verifies, the share
    /// is wrong, and the resulting session key silently decrypts to nothing
    /// usable. Prefer this method over [`SessionKeyShareProof::verify`].
    ///
    /// # Arguments
    ///
    /// * `share` - the session key share scalar `u_i` that was received
    /// * `blinding_commitment` - B_i = b_i * G (preconfigured commitment)
    /// * `rekey_commitment` - K_i = k_i * G (from factor commitments)
    ///
    /// # Returns
    ///
    /// `true` only if the proof verifies *and* the share matches it.
    pub fn verify_share<S: SessionKeyShare<Group = G>>(
        &self,
        share: &S,
        blinding_commitment: &BlindingCommitment<G>,
        rekey_commitment: &G::Element,
    ) -> bool {
        self.verify(blinding_commitment, rekey_commitment) && self.matches_share(share)
    }

    /// Whether `U_i == u_i · G` for the given share scalar.
    ///
    /// This is only the binding half of the check; on its own it says nothing
    /// about whether the proof is valid. Use [`SessionKeyShareProof::verify_share`]
    /// unless the proof has already been verified separately.
    ///
    /// Both sides are public group elements (`U_i` is published by the
    /// transcryptor and `u_i · G` is derived from it), so an ordinary equality
    /// comparison is appropriate here; the secret scalar itself is never
    /// compared.
    pub fn matches_share<S: SessionKeyShare<Group = G>>(&self, share: &S) -> bool {
        *share.value() * G::generator() == *self.share_commitment()
    }

    /// Verify a session key share proof, *without* binding it to any share.
    ///
    /// Checks that:
    /// 1. The proof is valid (proves knowledge of b_i)
    /// 2. U_i = b_i * K_i (using the blinding commitment)
    ///
    /// # This does not establish that any particular share is correct
    ///
    /// It never sees the share scalar `u_i`, so it cannot tell whether the
    /// share a user received corresponds to the `U_i` proven here. A user
    /// accepting a share MUST additionally check `U_i == u_i · G`; use
    /// [`SessionKeyShareProof::verify_share`], which does both. This method is
    /// for verifiers that only hold public values and never see a share.
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
        blinding_commitment: &BlindingCommitment<G>,
        rekey_commitment: &G::Element,
    ) -> bool {
        // Verify the ZKP
        // This confirms: proof.n = b_i * rekey_commitment
        // which means: U_i = b_i * K_i = b_i * (k_i * G) = (b_i * k_i) * G = u_i * G
        verify_proof::<G>(&blinding_commitment.0, rekey_commitment, &self.proof)
    }

    /// Get the public commitment to the session key share.
    ///
    /// Returns U_i = u_i * G. This is `self.proof.n()`: in the honest
    /// construction the proof's `n` value IS the share commitment.
    ///
    /// The user should verify the proof before relying on this value.
    pub fn share_commitment(&self) -> &G::Element {
        self.proof.n()
    }
}
