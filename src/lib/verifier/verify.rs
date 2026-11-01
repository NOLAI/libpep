//! The verifier and its commitment caches.

use super::cache::{
    AttributeRekeyCommitmentsCache, CommitmentsCache, PseudonymRekeyCommitmentsCache,
    PseudonymizationCommitmentsCache,
};
use super::errors::{RegisterCommitmentsError, VerifyError, WeakCommitmentError};
use crate::contexts::TranscryptorId;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::data::traits::Encrypted;
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable, VerifiableTranscryptable, VerifiableTranscryptionProof,
};
use crate::elgamal::arithmetic::ciphersuite::ElementOf;
use crate::elgamal::arithmetic::{Ciphersuite, Group};
use crate::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};
use crate::factors::commitments::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
#[cfg(feature = "verifiable-derivation")]
use crate::factors::verifiable::{MasterPseudonymizationPublicKey, MasterRekeyingPublicKey};
use crate::keys::distribution::proofs::{BlindingCommitment, SessionKeyShareProof};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::{PseudonymSessionPublicKey, SessionPublicKeys};
use std::collections::HashMap;

/// A verifier with per-transition commitment caching.
///
/// Stored commitments are *combined* for a given transition (i.e. already
/// encode the `s_from⁻¹·s_to` / `k_from⁻¹·k_to` product). Verification of
/// individual transcryption operations then reduces to a single
/// [`VerifiableRRSK`](crate::elgamal::verifiable::VerifiableRRSK) or
/// [`VerifiableRekey`](crate::elgamal::verifiable::VerifiableRekey) check against
/// these commitments.
pub struct Verifier<C: Ciphersuite = Ristretto255Sha512> {
    pseudonymization_cache: PseudonymizationCommitmentsCache<C::Group>,
    pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache<C::Group>,
    attribute_rekey_cache: AttributeRekeyCommitmentsCache<C::Group>,
    /// Blinding commitments per transcryptor, for session-key-share verification.
    blinding_commitments: HashMap<TranscryptorId, BlindingCommitment<C::Group>>,
    #[cfg(feature = "verifiable-derivation")]
    master_pseudonym_keys: HashMap<TranscryptorId, MasterPseudonymizationPublicKey<C>>,
    #[cfg(feature = "verifiable-derivation")]
    master_rekey_keys: HashMap<TranscryptorId, MasterRekeyingPublicKey<C>>,
}

/// Key identifying a pseudonymization transition.
pub type PseudonymizationKey = (
    TranscryptorId,
    PseudonymizationDomain,
    PseudonymizationDomain,
    EncryptionContext,
    EncryptionContext,
);

/// Key identifying a rekey transition.
pub type RekeyTransitionKey = (TranscryptorId, EncryptionContext, EncryptionContext);

impl Verifier {
    /// A verifier with empty, unbounded caches, for ristretto255 with SHA-512.
    ///
    /// See [`new_generic`](Verifier::new_generic) for another ciphersuite.
    #[must_use]
    pub fn new() -> Self {
        Self::new_generic()
    }

    /// A verifier with each commitment cache capped at `max_entries`, for ristretto255 with
    /// SHA-512. See [`with_cache_capacity_generic`](Verifier::with_cache_capacity_generic).
    #[must_use]
    pub fn with_cache_capacity(max_entries: usize) -> Self {
        Self::with_cache_capacity_generic(max_entries)
    }
}

impl<C: Ciphersuite> Verifier<C> {
    /// A verifier with empty, unbounded caches, for ciphersuite `C`.
    ///
    /// [`Verifier::new`] is this function for ristretto255 with SHA-512.
    #[must_use]
    pub fn new_generic() -> Self {
        Self {
            pseudonymization_cache: PseudonymizationCommitmentsCache::<C::Group>::new(),
            pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache::<C::Group>::new(),
            attribute_rekey_cache: AttributeRekeyCommitmentsCache::<C::Group>::new(),
            blinding_commitments: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_pseudonym_keys: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_rekey_keys: HashMap::new(),
        }
    }

    /// Construct a verifier with each commitment cache capped at
    /// `max_entries`. Once a cache is at its cap, further
    /// `register_*_commitments` calls return
    /// [`CacheRegistrationError::CacheFull`](super::cache::CacheRegistrationError::CacheFull)
    /// (wrapped in [`RegisterCommitmentsError`]). Idempotent re-registration
    /// of an existing key remains allowed at the cap.
    ///
    /// Use this when commitment registration is reachable from untrusted code
    /// and memory must be bounded.
    ///
    /// [`Verifier::with_cache_capacity`] is this function for ristretto255 with SHA-512.
    #[must_use]
    pub fn with_cache_capacity_generic(max_entries: usize) -> Self {
        Self {
            pseudonymization_cache: PseudonymizationCommitmentsCache::<C::Group>::with_max_entries(
                max_entries,
            ),
            pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache::<C::Group>::with_max_entries(
                max_entries,
            ),
            attribute_rekey_cache: AttributeRekeyCommitmentsCache::<C::Group>::with_max_entries(
                max_entries,
            ),
            blinding_commitments: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_pseudonym_keys: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_rekey_keys: HashMap::new(),
        }
    }

    // ------------------------------------------------------------------
    // Blinding commitments (for session key share verification)
    // ------------------------------------------------------------------

    /// Register the blinding commitment `B_i = b_i · G` of a transcryptor. A transcryptor has
    /// one blinding factor, used for its pseudonym and attribute session key shares alike.
    ///
    /// Rejects a weak commitment (identity or `G`): `B_i = G` would mean `b_i = 1`, which
    /// removes the blinding. Re-registering an already present transcryptor with a *different*
    /// commitment is also rejected (`ConflictingValue`): a session-share verifier with both an
    /// old and a new blinding commitment from the same transcryptor cannot safely decide which
    /// one was used.
    pub fn register_blinding_commitment(
        &mut self,
        transcryptor_id: TranscryptorId,
        commitment: BlindingCommitment<C::Group>,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&commitment.0, "blinding")?;
        match self.blinding_commitments.get(&transcryptor_id) {
            Some(existing) if *existing != commitment => {
                Err(super::cache::CacheRegistrationError::ConflictingValue.into())
            }
            _ => {
                self.blinding_commitments
                    .insert(transcryptor_id, commitment);
                Ok(())
            }
        }
    }

    /// The blinding commitment registered for a transcryptor.
    pub fn blinding_commitment(
        &self,
        transcryptor_id: &str,
    ) -> Option<&BlindingCommitment<C::Group>> {
        self.blinding_commitments.get(transcryptor_id)
    }

    /// Whether a blinding commitment is registered for a transcryptor.
    pub fn has_blinding_commitment(&self, transcryptor_id: &str) -> bool {
        self.blinding_commitments.contains_key(transcryptor_id)
    }

    // ------------------------------------------------------------------
    // Master keys (verifiable-derivation only)
    // ------------------------------------------------------------------

    /// Register the master public keys for a transcryptor (verifiable-derivation only).
    ///
    /// Rejects weak group elements (identity or `G`) in any master-key
    /// component, and rejects re-registration with a *different* key (a
    /// silent overwrite would invalidate everything previously cached against
    /// the prior master keys). Idempotent re-registration with the same
    /// values is allowed.
    #[cfg(feature = "verifiable-derivation")]
    pub fn register_master_keys(
        &mut self,
        transcryptor_id: TranscryptorId,
        pseudonym_master_key: MasterPseudonymizationPublicKey<C>,
        rekey_master_key: MasterRekeyingPublicKey<C>,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&pseudonym_master_key.x1, "master pseudonym x1")?;
        Self::validate_not_weak(&pseudonym_master_key.x2, "master pseudonym x2")?;
        Self::validate_not_weak(&rekey_master_key.y1, "master rekey y1")?;
        Self::validate_not_weak(&rekey_master_key.y2, "master rekey y2")?;
        if let Some(existing) = self.master_pseudonym_keys.get(&transcryptor_id) {
            if *existing != pseudonym_master_key {
                return Err(super::cache::CacheRegistrationError::ConflictingValue.into());
            }
        }
        if let Some(existing) = self.master_rekey_keys.get(&transcryptor_id) {
            if *existing != rekey_master_key {
                return Err(super::cache::CacheRegistrationError::ConflictingValue.into());
            }
        }
        self.master_pseudonym_keys
            .insert(transcryptor_id.clone(), pseudonym_master_key);
        self.master_rekey_keys
            .insert(transcryptor_id, rekey_master_key);
        Ok(())
    }

    #[cfg(feature = "verifiable-derivation")]
    /// The master pseudonymization public key registered for a transcryptor.
    pub fn get_master_pseudonym_key(
        &self,
        transcryptor_id: &str,
    ) -> Option<&MasterPseudonymizationPublicKey<C>> {
        self.master_pseudonym_keys.get(transcryptor_id)
    }

    #[cfg(feature = "verifiable-derivation")]
    /// The master rekeying public key registered for a transcryptor.
    pub fn get_master_rekey_key(
        &self,
        transcryptor_id: &str,
    ) -> Option<&MasterRekeyingPublicKey<C>> {
        self.master_rekey_keys.get(transcryptor_id)
    }

    #[cfg(feature = "verifiable-derivation")]
    /// Whether master keys are registered for a transcryptor.
    pub fn has_master_keys(&self, transcryptor_id: &str) -> bool {
        self.master_pseudonym_keys.contains_key(transcryptor_id)
            && self.master_rekey_keys.contains_key(transcryptor_id)
    }

    // ------------------------------------------------------------------
    // Commitment validation
    // ------------------------------------------------------------------

    fn validate_not_weak(
        val: &ElementOf<C>,
        commitment_type: &'static str,
    ) -> Result<(), WeakCommitmentError> {
        if *val == C::Group::identity() || *val == C::Group::generator() {
            Err(WeakCommitmentError(commitment_type))
        } else {
            Ok(())
        }
    }

    /// Reject a [`VerifiablePseudonymizationCommitment`] whose reshuffle or
    /// rekey component is weak (identity or `G`). Used by every one-shot
    /// `verify_*` / `verified_reconstruct_*` entry point so that callers who
    /// bypass [`register_pseudonymization_commitments`] still get the same
    /// guard.
    fn check_pseudonymization_commitment(
        c: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<(), VerifyError> {
        Self::validate_not_weak(&c.reshuffle_commitment.point(), "reshuffle").map_err(|e| {
            VerifyError::WeakCommitment {
                commitment_type: e.0,
            }
        })?;
        Self::validate_not_weak(&c.rekey_commitment.point(), "rekey").map_err(|e| {
            VerifyError::WeakCommitment {
                commitment_type: e.0,
            }
        })?;
        Ok(())
    }

    /// As [`check_pseudonymization_commitment`] but for a single rekey
    /// commitment.
    fn check_rekey_commitment(
        c: &VerifiableRekeyCommitment<C::Group>,
        kind: &'static str,
    ) -> Result<(), VerifyError> {
        Self::validate_not_weak(&c.commitment.point(), kind).map_err(|e| {
            VerifyError::WeakCommitment {
                commitment_type: e.0,
            }
        })
    }

    /// As [`check_pseudonymization_commitment`] but for a composite
    /// transcryption commitment (pseudonym + attribute).
    fn check_transcryption_commitment(
        c: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<(), VerifyError> {
        Self::check_pseudonymization_commitment(&c.pseudonym)?;
        Self::check_rekey_commitment(&c.attribute, "attribute rekey")
    }

    /// Register the combined commitments of a pseudonymization transition; weak commitments and
    /// conflicts with earlier registrations are refused.
    pub fn register_pseudonymization_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&commitments.reshuffle_commitment.point(), "reshuffle")?;
        Self::validate_not_weak(&commitments.rekey_commitment.point(), "rekey")?;
        let key: PseudonymizationKey = (
            transcryptor_id.clone(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        self.pseudonymization_cache.store(key, commitments)?;
        Ok(())
    }

    /// Register the combined commitment of a pseudonym rekey transition; weak commitments and
    /// conflicts with earlier registrations are refused.
    pub fn register_pseudonym_rekey_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: VerifiableRekeyCommitment<C::Group>,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&commitments.commitment.point(), "pseudonym rekey")?;
        let key: RekeyTransitionKey = (
            transcryptor_id.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        self.pseudonym_rekey_cache.store(key, commitments)?;
        Ok(())
    }

    /// Register the combined commitment of an attribute rekey transition; weak commitments and
    /// conflicts with earlier registrations are refused.
    pub fn register_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: VerifiableRekeyCommitment<C::Group>,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&commitments.commitment.point(), "attribute rekey")?;
        let key: RekeyTransitionKey = (
            transcryptor_id.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        self.attribute_rekey_cache.store(key, commitments)?;
        Ok(())
    }

    /// The registered commitments of a pseudonymization transition.
    pub fn pseudonymization_commitments(
        &self,
        transcryptor_id: &str,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Option<&VerifiablePseudonymizationCommitment<C::Group>> {
        let key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        self.pseudonymization_cache.retrieve(&key)
    }

    /// The registered commitment of a pseudonym rekey transition.
    pub fn pseudonym_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Option<&VerifiableRekeyCommitment<C::Group>> {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        self.pseudonym_rekey_cache.retrieve(&key)
    }

    /// The registered commitment of an attribute rekey transition.
    pub fn attribute_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Option<&VerifiableRekeyCommitment<C::Group>> {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        self.attribute_rekey_cache.retrieve(&key)
    }

    /// Whether commitments are registered for a pseudonymization transition.
    pub fn has_pseudonymization_commitments(
        &self,
        transcryptor_id: &str,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool {
        let key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        self.pseudonymization_cache.has(&key)
    }

    /// Whether a commitment is registered for a pseudonym rekey transition.
    pub fn has_pseudonym_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        self.pseudonym_rekey_cache.has(&key)
    }

    /// Whether a commitment is registered for an attribute rekey transition.
    pub fn has_attribute_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        self.attribute_rekey_cache.has(&key)
    }

    /// The commitment caches, for their sizes.
    pub fn cache(&self) -> VerifierCache<'_, C::Group> {
        VerifierCache {
            pseudonymization: &self.pseudonymization_cache,
            pseudonym_rekey: &self.pseudonym_rekey_cache,
            attribute_rekey: &self.attribute_rekey_cache,
        }
    }

    /// Forget every registered commitment.
    pub fn clear_cache(&mut self) {
        self.pseudonymization_cache.clear();
        self.pseudonym_rekey_cache.clear();
        self.attribute_rekey_cache.clear();
    }

    // ------------------------------------------------------------------
    // Operation verification with explicit commitments
    // ------------------------------------------------------------------

    // ----- Rekey -----

    /// Verify a rekey proof against the given commitment.
    pub fn verify_rekey<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableRekeyCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableRekeyProof<Group = C::Group>,
    {
        Self::check_rekey_commitment(commitments, "rekey")?;
        if proof.verify::<C>(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    /// Verify a rekey proof against the given commitment and return the rekeyed value.
    pub fn verified_reconstruct_rekey<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableRekeyCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableRekeyProof<Group = C::Group>,
    {
        Self::check_rekey_commitment(commitments, "rekey")?;
        proof
            .verified_reconstruct::<C>(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ----- Pseudonymization -----

    #[cfg(feature = "elgamal3")]
    /// Verify a pseudonymization proof against the given commitments.
    pub fn verify_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        if proof.verify::<C>(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a pseudonymization proof against the given commitments; `public_key` is the key the
    /// original was encrypted under.
    pub fn verify_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &PseudonymSessionPublicKey<C::Group>,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        if proof.verify::<C>(original, public_key, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(feature = "elgamal3")]
    /// Verify a pseudonymization proof against the given commitments and return the pseudonymized
    /// value.
    pub fn verified_reconstruct_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a pseudonymization proof against the given commitments and return the pseudonymized
    /// value; `public_key` is the key the original was encrypted under.
    pub fn verified_reconstruct_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &PseudonymSessionPublicKey<C::Group>,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, public_key, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ----- Transcryption (composite) -----

    #[cfg(feature = "elgamal3")]
    /// Verify a transcryption proof against the given commitments.
    pub fn verify_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        if proof.verify::<C>(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a transcryption proof against the given commitments; `public_key` holds the keys
    /// the original was encrypted under.
    pub fn verify_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &SessionPublicKeys<C::Group>,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        if proof.verify::<C>(original, public_key, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(feature = "elgamal3")]
    /// Verify a transcryption proof against the given commitments and return the transcrypted
    /// value.
    pub fn verified_reconstruct_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a transcryption proof against the given commitments and return the transcrypted
    /// value; `public_key` holds the keys the original was encrypted under.
    pub fn verified_reconstruct_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &SessionPublicKeys<C::Group>,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, public_key, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ------------------------------------------------------------------
    // Operation verification using cached commitments
    // ------------------------------------------------------------------

    /// Verify a pseudonymization proof using cached commitments for the
    /// given transition.
    #[cfg(feature = "elgamal3")]
    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct_pseudonymization_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::PseudonymizationProof,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::PseudonymizationProof as VerifiablePseudonymizationProof>::Output, VerifyError>
    where
        E: VerifiablePseudonymizable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::PseudonymizationProof: VerifiablePseudonymizationProof<DataType = E>,
    {
        let key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .pseudonymization_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_pseudonymization::<E::PseudonymizationProof>(
            original,
            proof,
            commitments,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    /// Verify a pseudonymization proof against the cached commitments of the transition and
    /// return the pseudonymized value; `public_key` is the key the original was encrypted under.
    pub fn verified_reconstruct_pseudonymization_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::PseudonymizationProof,
        public_key: &PseudonymSessionPublicKey<C::Group>,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::PseudonymizationProof as VerifiablePseudonymizationProof>::Output, VerifyError>
    where
        E: VerifiablePseudonymizable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::PseudonymizationProof: VerifiablePseudonymizationProof<DataType = E>,
    {
        let key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .pseudonymization_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_pseudonymization::<E::PseudonymizationProof>(
            original,
            proof,
            public_key,
            commitments,
        )
    }

    /// Verify a pseudonym rekey proof against the cached commitment of the transition and return
    /// the rekeyed value.
    pub fn verified_reconstruct_pseudonym_rekey_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::RekeyProof,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::RekeyProof as VerifiableRekeyProof>::Output, VerifyError>
    where
        E: VerifiableRekeyable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::RekeyProof: VerifiableRekeyProof<DataType = E>,
    {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .pseudonym_rekey_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_rekey::<E::RekeyProof>(original, proof, commitments)
    }

    /// Verify an attribute rekey proof against the cached commitment of the transition and return
    /// the rekeyed value.
    pub fn verified_reconstruct_attribute_rekey_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::RekeyProof,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::RekeyProof as VerifiableRekeyProof>::Output, VerifyError>
    where
        E: VerifiableRekeyable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::RekeyProof: VerifiableRekeyProof<DataType = E>,
    {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .attribute_rekey_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_rekey::<E::RekeyProof>(original, proof, commitments)
    }

    /// Verify a composite-value transcryption proof using cached commitments.
    #[cfg(feature = "elgamal3")]
    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct_transcryption_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::TranscryptionProof,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::TranscryptionProof as VerifiableTranscryptionProof>::Output, VerifyError>
    where
        E: VerifiableTranscryptable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::TranscryptionProof: VerifiableTranscryptionProof<DataType = E>,
    {
        let pseudo_key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let attr_key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let pseudonym = *self
            .pseudonymization_cache
            .retrieve(&pseudo_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let attribute = *self
            .attribute_rekey_cache
            .retrieve(&attr_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let commitments = VerifiableTranscryptionCommitment {
            pseudonym,
            attribute,
        };
        self.verified_reconstruct_transcryption::<E::TranscryptionProof>(
            original,
            proof,
            &commitments,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    /// Verify a transcryption proof against the cached commitments of the transition and return
    /// the transcrypted value; `public_key` holds the keys the original was encrypted under.
    pub fn verified_reconstruct_transcryption_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::TranscryptionProof,
        public_key: &SessionPublicKeys<C::Group>,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::TranscryptionProof as VerifiableTranscryptionProof>::Output, VerifyError>
    where
        E: VerifiableTranscryptable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::TranscryptionProof: VerifiableTranscryptionProof<DataType = E>,
    {
        let pseudo_key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let attr_key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let pseudonym = *self
            .pseudonymization_cache
            .retrieve(&pseudo_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let attribute = *self
            .attribute_rekey_cache
            .retrieve(&attr_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let commitments = VerifiableTranscryptionCommitment {
            pseudonym,
            attribute,
        };
        self.verified_reconstruct_transcryption::<E::TranscryptionProof>(
            original,
            proof,
            public_key,
            &commitments,
        )
    }

    // ------------------------------------------------------------------
    // Session key share verification
    // ------------------------------------------------------------------

    // Session-share verification requires the session-level rekey
    // commitment, which the verifier does not cache (commitments are
    // per-transition). Use [`verify_session_key_share_with_commitment`]
    // and supply the rekey commitment explicitly.

    /// Verify a session-key-share proof against the registered blinding commitment of the
    /// transcryptor and an explicitly supplied rekey commitment.
    pub fn verify_session_key_share_with_commitment(
        &self,
        transcryptor_id: &str,
        rekey_commitment: &ElementOf<C>,
        proof: &SessionKeyShareProof<C::Group>,
    ) -> Result<(), VerifyError> {
        let blinding_commitment = self
            .blinding_commitment(transcryptor_id)
            .ok_or(VerifyError::UnknownCommitment)?;
        if proof.verify::<C>(blinding_commitment, rekey_commitment) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }
}

/// Read-only view of the verifier's cache.
pub struct VerifierCache<'a, G: Group = Ristretto255> {
    pseudonymization: &'a PseudonymizationCommitmentsCache<G>,
    pseudonym_rekey: &'a PseudonymRekeyCommitmentsCache<G>,
    attribute_rekey: &'a AttributeRekeyCommitmentsCache<G>,
}

impl<G: Group> VerifierCache<'_, G> {
    /// Whether no commitments are cached.
    pub fn is_empty(&self) -> bool {
        self.pseudonymization.is_empty()
            && self.pseudonym_rekey.is_empty()
            && self.attribute_rekey.is_empty()
    }

    /// The number of cached commitments over all transitions.
    pub fn total_count(&self) -> usize {
        self.pseudonymization.len() + self.pseudonym_rekey.len() + self.attribute_rekey.len()
    }

    /// The number of cached pseudonymization transitions.
    pub fn pseudonymization_count(&self) -> usize {
        self.pseudonymization.len()
    }

    /// The number of cached pseudonym rekey transitions.
    pub fn pseudonym_rekey_count(&self) -> usize {
        self.pseudonym_rekey.len()
    }

    /// The number of cached attribute rekey transitions.
    pub fn attribute_rekey_count(&self) -> usize {
        self.attribute_rekey.len()
    }
}

impl<C: Ciphersuite> Default for Verifier<C> {
    fn default() -> Self {
        Self::new_generic()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::contexts::{EncryptionContext, PseudonymizationDomain};
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};
    use crate::elgamal::verifiable::{
        FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
    };
    use crate::factors::VerifiablePseudonymizationCommitment;

    type Verifier = super::Verifier<Ristretto255Sha512>;

    fn weak_pseudonymization_commitments(
        weak: GroupElement,
    ) -> VerifiablePseudonymizationCommitment<Ristretto255> {
        VerifiablePseudonymizationCommitment {
            reshuffle_commitment: PseudonymizationFactorCommitment(FactorCommitment(weak)),
            rekey_commitment: RekeyFactorCommitment(FactorCommitment(weak)),
        }
    }

    #[test]
    fn register_rejects_weak_commitments_without_panicking() {
        let mut verifier = Verifier::new();
        let id = String::from("t1");
        let d1 = PseudonymizationDomain::from("d1");
        let d2 = PseudonymizationDomain::from("d2");
        let c1 = EncryptionContext::from("c1");
        let c2 = EncryptionContext::from("c2");

        // Identity commitments must be rejected with an Err, not a panic.
        let identity_commitments = weak_pseudonymization_commitments(GroupElement::identity());
        assert!(verifier
            .register_pseudonymization_commitments(&id, &d1, &d2, &c1, &c2, identity_commitments)
            .is_err());

        // Generator-equal commitments must also be rejected.
        let g_commitments = weak_pseudonymization_commitments(G);
        assert!(verifier
            .register_pseudonymization_commitments(&id, &d1, &d2, &c1, &c2, g_commitments)
            .is_err());

        // Cache must remain untouched after a failed registration.
        assert!(verifier.cache().is_empty());
    }
}
