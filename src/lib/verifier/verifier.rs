//! Verifier for verifiable transcryption operations.
//!
//! The verifier checks that operations were performed against published
//! forward commitments. Concretely:
//!
//!   * For a pseudonymization transition `(d_from, d_to, c_from, c_to)` the
//!     transcryptor publishes the *combined* commitments
//!     `S = (s_from⁻¹ · s_to)·G` and `K = (k_from⁻¹ · k_to)·G`. The verifier
//!     stores them under the chosen transition key.
//!   * For an attribute rekey transition `(c_from, c_to)` the transcryptor
//!     publishes the combined commitment `K = (k_from⁻¹ · k_to)·G`.
//!   * Per-message verifiable proofs are verified against those combined
//!     commitments.
//!
//! No proof of well-formedness of the commitments themselves is needed any
//! more: every per-message proof binds the operation to the forward
//! commitment directly.
//!
//! # Per-message vs batch verification
//!
//! This module exposes verification for *per-message* proofs:
//! [`verify_pseudonymization`](Verifier::verify_pseudonymization),
//! [`verify_rekey`](Verifier::verify_rekey), and
//! [`verify_transcryption`](Verifier::verify_transcryption) (for composite
//! record/JSON values). Each is polymorphic over any encrypted type
//! implementing the matching `Verifiable*` trait (simple values, long
//! values, records, JSON).
//!
//! Batch proofs are verified through the
//! [`EncryptedBatch`](crate::data::batch::EncryptedBatch) type directly
//! (`batch.verified_reconstruct_pseudonymize`, `verified_reconstruct_rekey`,
//! `verified_reconstruct_transcrypt`). Those methods take commitments
//! explicitly; if you want cached-commitment lookup at batch level, fetch
//! the commitments from this verifier's cache (`has_*_commitments` query
//! APIs) and pass them into the batch method.

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable, VerifiableTranscryptable, VerifiableTranscryptionProof,
};
use crate::factors::{
    EncryptionContext, PseudonymizationDomain, VerifiablePseudonymizationCommitment,
    VerifiableRekeyCommitment, VerifiableTranscryptionCommitment,
};
use crate::keys::distribution::BlindingCommitments;
use crate::transcryptor::TranscryptorId;
use std::collections::HashMap;

#[cfg(feature = "verifiable-derivation")]
use crate::factors::{MasterPseudonymizationPublicKey, MasterRekeyingPublicKey};

use super::cache::{
    AttributeRekeyCommitmentsCache, CommitmentsCache as CommitmentsCacheTrait,
    PseudonymRekeyCommitmentsCache, PseudonymizationCommitmentsCache,
};

/// A commitment was the identity or the generator `G`, which would let any
/// per-message proof trivially "verify" without binding anything.
#[derive(thiserror::Error, Debug, Clone, Copy, Eq, PartialEq)]
#[error("weak {0} commitment is not allowed")]
pub struct WeakCommitmentError(pub &'static str);

/// Failure mode for `register_*_commitments` calls. Either the supplied
/// commitment is weak, or the cache rejected the registration (conflicting
/// value already present, or cache is full).
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum RegisterCommitmentsError {
    #[error(transparent)]
    Weak(#[from] WeakCommitmentError),
    #[error(transparent)]
    Cache(#[from] super::cache::CacheRegistrationError),
}

/// Structured failure mode for `verify_*` / `verified_reconstruct_*` methods.
///
/// Distinguishes between cryptographic failure (`ProofRejected`), a cache
/// miss (`UnknownCommitment`), a weak / unusable commitment, and the absence
/// of master keys (only relevant on the `verifiable-derivation` path).
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum VerifyError {
    /// The proof did not verify against the supplied statement.
    #[error("proof rejected")]
    ProofRejected,
    /// No commitments registered for the requested transcryptor/transition.
    #[error("no commitments registered for this transition")]
    UnknownCommitment,
    /// Commitments are present but are weak / invalid.
    #[error("weak {commitment_type} commitment")]
    WeakCommitment { commitment_type: &'static str },
    /// Master keys are not registered (needed for verifiable-derivation paths).
    #[error("master keys not registered for this transcryptor")]
    MasterKeysNotRegistered,
}

/// A verifier with per-transition commitment caching.
///
/// Stored commitments are *combined* for a given transition (i.e. already
/// encode the `s_from⁻¹·s_to` / `k_from⁻¹·k_to` product). Verification of
/// individual transcryption operations then reduces to a single
/// [`VerifiableRRSK`](crate::core::verifiable::VerifiableRRSK) or
/// [`VerifiableRekey`](crate::core::verifiable::VerifiableRekey) check against
/// these commitments.
pub struct Verifier {
    pseudonymization_cache: PseudonymizationCommitmentsCache,
    pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache,
    attribute_rekey_cache: AttributeRekeyCommitmentsCache,
    /// Blinding commitments per transcryptor, for session-key-share verification.
    blinding_commitments: HashMap<TranscryptorId, BlindingCommitments>,
    #[cfg(feature = "verifiable-derivation")]
    master_pseudonym_keys: HashMap<TranscryptorId, MasterPseudonymizationPublicKey>,
    #[cfg(feature = "verifiable-derivation")]
    master_rekey_keys: HashMap<TranscryptorId, MasterRekeyingPublicKey>,
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            pseudonymization_cache: PseudonymizationCommitmentsCache::new(),
            pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache::new(),
            attribute_rekey_cache: AttributeRekeyCommitmentsCache::new(),
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

    pub fn register_blinding_commitments(
        &mut self,
        transcryptor_id: TranscryptorId,
        commitments: BlindingCommitments,
    ) {
        self.blinding_commitments
            .insert(transcryptor_id, commitments);
    }

    pub fn get_blinding_commitments(&self, transcryptor_id: &str) -> Option<&BlindingCommitments> {
        self.blinding_commitments.get(transcryptor_id)
    }

    pub fn has_blinding_commitments(&self, transcryptor_id: &str) -> bool {
        self.blinding_commitments.contains_key(transcryptor_id)
    }

    // ------------------------------------------------------------------
    // Master keys (verifiable-derivation only)
    // ------------------------------------------------------------------

    #[cfg(feature = "verifiable-derivation")]
    pub fn register_master_keys(
        &mut self,
        transcryptor_id: TranscryptorId,
        pseudonym_master_key: MasterPseudonymizationPublicKey,
        rekey_master_key: MasterRekeyingPublicKey,
    ) {
        self.master_pseudonym_keys
            .insert(transcryptor_id.clone(), pseudonym_master_key);
        self.master_rekey_keys
            .insert(transcryptor_id, rekey_master_key);
    }

    #[cfg(feature = "verifiable-derivation")]
    pub fn get_master_pseudonym_key(
        &self,
        transcryptor_id: &str,
    ) -> Option<&MasterPseudonymizationPublicKey> {
        self.master_pseudonym_keys.get(transcryptor_id)
    }

    #[cfg(feature = "verifiable-derivation")]
    pub fn get_master_rekey_key(&self, transcryptor_id: &str) -> Option<&MasterRekeyingPublicKey> {
        self.master_rekey_keys.get(transcryptor_id)
    }

    #[cfg(feature = "verifiable-derivation")]
    pub fn has_master_keys(&self, transcryptor_id: &str) -> bool {
        self.master_pseudonym_keys.contains_key(transcryptor_id)
            && self.master_rekey_keys.contains_key(transcryptor_id)
    }

    // ------------------------------------------------------------------
    // Commitment validation
    // ------------------------------------------------------------------

    fn validate_not_weak(
        val: &GroupElement,
        commitment_type: &'static str,
    ) -> Result<(), WeakCommitmentError> {
        if *val == GroupElement::identity() || *val == G {
            Err(WeakCommitmentError(commitment_type))
        } else {
            Ok(())
        }
    }

    pub fn register_pseudonymization_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: VerifiablePseudonymizationCommitment,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&commitments.reshuffle_commitment.0 .0, "reshuffle")?;
        Self::validate_not_weak(&commitments.rekey_commitment.0 .0, "rekey")?;
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

    pub fn register_pseudonym_rekey_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: VerifiableRekeyCommitment,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&commitments.commitment.0 .0, "pseudonym rekey")?;
        let key: RekeyTransitionKey = (
            transcryptor_id.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        self.pseudonym_rekey_cache.store(key, commitments)?;
        Ok(())
    }

    pub fn register_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: VerifiableRekeyCommitment,
    ) -> Result<(), RegisterCommitmentsError> {
        Self::validate_not_weak(&commitments.commitment.0 .0, "attribute rekey")?;
        let key: RekeyTransitionKey = (
            transcryptor_id.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        self.attribute_rekey_cache.store(key, commitments)?;
        Ok(())
    }

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

    pub fn cache(&self) -> VerifierCache<'_> {
        VerifierCache {
            pseudonymization: &self.pseudonymization_cache,
            pseudonym_rekey: &self.pseudonym_rekey_cache,
            attribute_rekey: &self.attribute_rekey_cache,
        }
    }

    pub fn clear_cache(&mut self) {
        self.pseudonymization_cache.clear();
        self.pseudonym_rekey_cache.clear();
        self.attribute_rekey_cache.clear();
    }

    // ------------------------------------------------------------------
    // Operation verification with explicit commitments
    // ------------------------------------------------------------------

    // ----- Rekey -----

    pub fn verify_rekey<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableRekeyCommitment,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableRekeyProof,
    {
        if proof.verify(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    pub fn verified_reconstruct_rekey<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableRekeyCommitment,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableRekeyProof,
    {
        proof
            .verified_reconstruct(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ----- Pseudonymization -----

    #[cfg(feature = "elgamal3")]
    pub fn verify_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiablePseudonymizationCommitment,
    ) -> Result<(), VerifyError>
    where
        P: VerifiablePseudonymizationProof,
    {
        if proof.verify(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &VerifiablePseudonymizationCommitment,
    ) -> Result<(), VerifyError>
    where
        P: VerifiablePseudonymizationProof,
    {
        if proof.verify(original, public_key, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiablePseudonymizationCommitment,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiablePseudonymizationProof,
    {
        proof
            .verified_reconstruct(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &VerifiablePseudonymizationCommitment,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiablePseudonymizationProof,
    {
        proof
            .verified_reconstruct(original, public_key, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ----- Transcryption (composite) -----

    #[cfg(feature = "elgamal3")]
    pub fn verify_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableTranscryptionCommitment,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableTranscryptionProof,
    {
        if proof.verify(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &crate::keys::SessionKeys,
        commitments: &VerifiableTranscryptionCommitment,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableTranscryptionProof,
    {
        if proof.verify(original, public_key, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableTranscryptionCommitment,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableTranscryptionProof,
    {
        proof
            .verified_reconstruct(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &crate::keys::SessionKeys,
        commitments: &VerifiableTranscryptionCommitment,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableTranscryptionProof,
    {
        proof
            .verified_reconstruct(original, public_key, commitments)
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
        E: VerifiablePseudonymizable,
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
    pub fn verified_reconstruct_pseudonymization_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::PseudonymizationProof,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::PseudonymizationProof as VerifiablePseudonymizationProof>::Output, VerifyError>
    where
        E: VerifiablePseudonymizable,
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

    pub fn verified_reconstruct_pseudonym_rekey_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::RekeyProof,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::RekeyProof as VerifiableRekeyProof>::Output, VerifyError>
    where
        E: VerifiableRekeyable,
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

    pub fn verified_reconstruct_attribute_rekey_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::RekeyProof,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::RekeyProof as VerifiableRekeyProof>::Output, VerifyError>
    where
        E: VerifiableRekeyable,
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
        E: VerifiableTranscryptable,
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
    pub fn verified_reconstruct_transcryption_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::TranscryptionProof,
        public_key: &crate::keys::SessionKeys,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::TranscryptionProof as VerifiableTranscryptionProof>::Output, VerifyError>
    where
        E: VerifiableTranscryptable,
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

    // Note: session-share verification requires the session-level rekey
    // commitment, which the verifier no longer caches per-context (commitments
    // are now per-transition). Use [`verify_session_key_share_with_commitment`]
    // and supply the rekey commitment explicitly.

    /// Verify a session-key-share proof with an explicitly supplied rekey commitment.
    pub fn verify_session_key_share_with_commitment(
        &self,
        transcryptor_id: &str,
        rekey_commitment: &GroupElement,
        for_pseudonym: bool,
        proof: &crate::keys::distribution::SessionKeyShareProof,
    ) -> Result<(), VerifyError> {
        let blinding_commitments = self
            .get_blinding_commitments(transcryptor_id)
            .ok_or(VerifyError::UnknownCommitment)?;
        let bc = if for_pseudonym {
            &blinding_commitments.pseudonym
        } else {
            &blinding_commitments.attribute
        };
        if proof.verify(bc, rekey_commitment) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }
}

/// Read-only view of the verifier's cache.
pub struct VerifierCache<'a> {
    pseudonymization: &'a PseudonymizationCommitmentsCache,
    pseudonym_rekey: &'a PseudonymRekeyCommitmentsCache,
    attribute_rekey: &'a AttributeRekeyCommitmentsCache,
}

impl<'a> VerifierCache<'a> {
    pub fn is_empty(&self) -> bool {
        self.pseudonymization.is_empty()
            && self.pseudonym_rekey.is_empty()
            && self.attribute_rekey.is_empty()
    }

    pub fn total_count(&self) -> usize {
        self.pseudonymization.len() + self.pseudonym_rekey.len() + self.attribute_rekey.len()
    }

    pub fn pseudonymization_count(&self) -> usize {
        self.pseudonymization.len()
    }

    pub fn pseudonym_rekey_count(&self) -> usize {
        self.pseudonym_rekey.len()
    }

    pub fn attribute_rekey_count(&self) -> usize {
        self.attribute_rekey.len()
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::verifiable::{
        FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
    };

    fn weak_pseudonymization_commitments(
        weak: GroupElement,
    ) -> VerifiablePseudonymizationCommitment {
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
