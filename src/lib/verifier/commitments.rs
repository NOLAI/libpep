//! The commitment registry of the [`Verifier`]: blinding commitments, master keys, and the
//! validated, cached transition commitments.

use super::cache::CommitmentsCache;
use super::errors::{RegisterCommitmentsError, VerifyError, WeakCommitmentError};
use super::verify::{PseudonymizationKey, RekeyTransitionKey, Verifier, VerifierCache};
use crate::contexts::TranscryptorId;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::ciphersuite::ElementOf;
use crate::elgamal::arithmetic::{Ciphersuite, Group};
use crate::factors::commitments::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
#[cfg(feature = "verifiable-derivation")]
use crate::factors::verifiable::{MasterPseudonymizationPublicKey, MasterRekeyingPublicKey};
use crate::keys::distribution::proofs::BlindingCommitment;

impl<C: Ciphersuite> Verifier<C> {
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
    pub(super) fn check_pseudonymization_commitment(
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
    pub(super) fn check_rekey_commitment(
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
    pub(super) fn check_transcryption_commitment(
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
}
