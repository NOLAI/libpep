//! Verifier for verifiable transcryption operations.
//!
//! The verifier enforces integrity by ensuring transcryptors use consistent factors
//! for each user (domain) and session (context), as described in the paper.
//!
//! This implementation follows the pattern from the distributed verifier, storing
//! verified commitments per individual domain/context and combining them for
//! verification of transitions.

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::core::proved::{
    PseudonymizationFactorCommitments, RekeyFactorCommitments, RSKFactorsProof, VerifiableRekey,
    VerifiableRSK,
};
use crate::data::simple::{ElGamalEncrypted, EncryptedPseudonym};
use crate::data::traits::{Pseudonymizable, Rekeyable};
use crate::data::records::{EncryptedRecord, RecordTranscryptionProof};
use crate::factors::{
    EncryptionContext, ProvedPseudonymizationCommitments, ProvedRekeyCommitments,
    ProvedReshuffleCommitments, PseudonymizationDomain,
};
use crate::transcryptor::TranscryptorId;

use super::cache::{
    AttributeRekeyCommitmentsCache, CommitmentsCache as CommitmentsCacheTrait,
    PseudonymRekeyCommitmentsCache, ReshuffleCommitmentsCache,
};

/// A verifier for verifiable transcryption operations with commitment caching.
///
/// The verifier ensures integrity by checking that transcryptors use consistent
/// factors for each user and session:
/// - **Reshuffle factors** must be consistent per pseudonymization domain (user-specific)
/// - **Rekey factors** must be consistent per encryption context (session-specific)
///
/// # Cache Organization
///
/// The verifier maintains three separate caches:
/// - Reshuffle commitments indexed by `PseudonymizationDomain`
/// - Pseudonym rekey commitments indexed by `EncryptionContext`
/// - Attribute rekey commitments indexed by `EncryptionContext`
///
/// Each cache stores both `val` and `inv` for the factor commitments.
pub struct Verifier {
    reshuffle_cache: ReshuffleCommitmentsCache,
    pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache,
    attribute_rekey_cache: AttributeRekeyCommitmentsCache,
}

impl Verifier {
    /// Create a new verifier with empty caches.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reshuffle_cache: ReshuffleCommitmentsCache::new(),
            pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache::new(),
            attribute_rekey_cache: AttributeRekeyCommitmentsCache::new(),
        }
    }

    // ========================================
    // Commitment validation and storage
    // ========================================

    /// Validate that commitments are not weak (identity or G).
    fn validate_not_weak(val: &GroupElement, commitment_type: &str) {
        if *val == GroupElement::identity() || *val == G {
            panic!("Weak {commitment_type} commitments are not allowed");
        }
    }

    /// Store reshuffle commitments for a transcryptor and domain after validation.
    ///
    /// This validates that:
    /// 1. The commitments are not weak (not identity or G)
    /// 2. The proof correctly verifies the commitments
    ///
    /// # Panics
    ///
    /// Panics if the commitments are weak or the proof is invalid.
    pub fn store_reshuffle_commitments(
        &mut self,
        transcryptor_id: TranscryptorId,
        domain: PseudonymizationDomain,
        commitments: &ProvedReshuffleCommitments,
    ) {
        Self::validate_not_weak(&commitments.commitments.val, "reshuffle");

        if !commitments.proof.verify(&commitments.commitments) {
            panic!("Invalid reshuffle commitments proof");
        }

        self.reshuffle_cache.store((transcryptor_id, domain), *commitments);
    }

    /// Store pseudonym rekey commitments for a transcryptor and context after validation.
    ///
    /// This validates that:
    /// 1. The commitments are not weak (not identity or G)
    /// 2. The proof correctly verifies the commitments
    ///
    /// # Panics
    ///
    /// Panics if the commitments are weak or the proof is invalid.
    pub fn store_pseudonym_rekey_commitments(
        &mut self,
        transcryptor_id: TranscryptorId,
        context: EncryptionContext,
        commitments: &ProvedRekeyCommitments,
    ) {
        Self::validate_not_weak(&commitments.commitments.val, "pseudonym rekey");

        if !commitments.proof.verify(&commitments.commitments) {
            panic!("Invalid pseudonym rekey commitments proof");
        }

        self.pseudonym_rekey_cache.store((transcryptor_id, context), *commitments);
    }

    /// Store attribute rekey commitments for a transcryptor and context after validation.
    ///
    /// This validates that:
    /// 1. The commitments are not weak (not identity or G)
    /// 2. The proof correctly verifies the commitments
    ///
    /// # Panics
    ///
    /// Panics if the commitments are weak or the proof is invalid.
    pub fn store_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: TranscryptorId,
        context: EncryptionContext,
        commitments: &ProvedRekeyCommitments,
    ) {
        Self::validate_not_weak(&commitments.commitments.val, "attribute rekey");

        if !commitments.proof.verify(&commitments.commitments) {
            panic!("Invalid attribute rekey commitments proof");
        }

        self.attribute_rekey_cache.store((transcryptor_id, context), *commitments);
    }

    // ========================================
    // Cache queries
    // ========================================

    /// Check if reshuffle commitments exist for a transcryptor and domain.
    #[must_use]
    pub fn has_reshuffle_commitments(&self, transcryptor_id: &str, domain: &PseudonymizationDomain) -> bool {
        self.reshuffle_cache.has(&(transcryptor_id.to_string(), domain.clone()))
    }

    /// Check if pseudonym rekey commitments exist for a transcryptor and context.
    #[must_use]
    pub fn has_pseudonym_rekey_commitments(&self, transcryptor_id: &str, context: &EncryptionContext) -> bool {
        self.pseudonym_rekey_cache.has(&(transcryptor_id.to_string(), context.clone()))
    }

    /// Check if attribute rekey commitments exist for a transcryptor and context.
    #[must_use]
    pub fn has_attribute_rekey_commitments(&self, transcryptor_id: &str, context: &EncryptionContext) -> bool {
        self.attribute_rekey_cache.has(&(transcryptor_id.to_string(), context.clone()))
    }

    // ========================================
    // Commitment registration (for test compatibility)
    // ========================================

    /// Register pseudonymization commitments for a domain/context transition.
    ///
    /// Note: Transition commitments are already combined (inv from source, val from target).
    /// This method stores them such that they can be used for verifying this specific transition.
    /// The commitments are stored once and shared between source/target domains and contexts.
    pub fn register_pseudonymization_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: ProvedPseudonymizationCommitments,
    ) {
        // Transition commitments are already combined, so we store them once
        // They will work for verifying the specific transition domain_from→domain_to, context_from→context_to
        let reshuffle_commitments = ProvedReshuffleCommitments {
            commitments: commitments.reshuffle_commitments,
            proof: commitments.reshuffle_proof,
        };

        let rekey_commitments = ProvedRekeyCommitments {
            commitments: commitments.rekey_commitments,
            proof: commitments.rekey_proof,
        };

        // Store once for each unique domain/context (avoid duplicates)
        let tid = transcryptor_id.clone();

        if !self.has_reshuffle_commitments(transcryptor_id, domain_from) {
            self.store_reshuffle_commitments(tid.clone(), domain_from.clone(), &reshuffle_commitments);
        }
        if domain_from != domain_to && !self.has_reshuffle_commitments(transcryptor_id, domain_to) {
            self.store_reshuffle_commitments(tid.clone(), domain_to.clone(), &reshuffle_commitments);
        }
        if !self.has_pseudonym_rekey_commitments(transcryptor_id, context_from) {
            self.store_pseudonym_rekey_commitments(tid.clone(), context_from.clone(), &rekey_commitments);
        }
        if context_from != context_to && !self.has_pseudonym_rekey_commitments(transcryptor_id, context_to) {
            self.store_pseudonym_rekey_commitments(tid, context_to.clone(), &rekey_commitments);
        }
    }

    /// Register attribute rekey commitments for a transcryptor's context transition.
    pub fn register_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: &TranscryptorId,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
        commitments: ProvedRekeyCommitments,
    ) {
        // Store for both source and target if not already present
        let tid = transcryptor_id.clone();

        if !self.has_attribute_rekey_commitments(transcryptor_id, context_from) {
            self.store_attribute_rekey_commitments(tid.clone(), context_from.clone(), &commitments);
        }
        if context_from != context_to && !self.has_attribute_rekey_commitments(transcryptor_id, context_to) {
            self.store_attribute_rekey_commitments(tid, context_to.clone(), &commitments);
        }
    }

    /// Get cached pseudonymization commitments for a transition (if registered).
    ///
    /// Note: This method is deprecated in the new architecture. Commitments are stored
    /// separately per domain/context, not as bundled transitions. This always returns None.
    #[must_use]
    #[deprecated(note = "Commitments are now stored per domain/context, use has_reshuffle_commitments and has_pseudonym_rekey_commitments instead")]
    pub fn get_pseudonymization_commitments(
        &self,
        _domain_from: &PseudonymizationDomain,
        _domain_to: &PseudonymizationDomain,
        _context_from: &EncryptionContext,
        _context_to: &EncryptionContext,
    ) -> Option<&ProvedPseudonymizationCommitments> {
        // Commitments are stored separately per domain/context in the new architecture
        None
    }

    // ========================================
    // Commitment verification
    // ========================================

    /// Verify that pseudonymization commitments (reshuffle + rekey) are correctly constructed.
    #[must_use]
    pub fn verify_pseudonymization_commitments(
        &self,
        commitments: &ProvedPseudonymizationCommitments,
    ) -> bool {
        commitments
            .reshuffle_proof
            .verify(&commitments.reshuffle_commitments)
            && commitments.rekey_proof.verify(&commitments.rekey_commitments)
    }

    /// Verify that rekey commitments are correctly constructed.
    #[must_use]
    pub fn verify_rekey_commitments(&self, commitments: &ProvedRekeyCommitments) -> bool {
        commitments.proof.verify(&commitments.commitments)
    }

    // ========================================
    // Cache management
    // ========================================

    /// Access the internal cache (read-only).
    pub fn cache(&self) -> VerifierCache<'_> {
        VerifierCache {
            reshuffle: &self.reshuffle_cache,
            pseudonym_rekey: &self.pseudonym_rekey_cache,
            attribute_rekey: &self.attribute_rekey_cache,
        }
    }

    /// Clear all cached commitments.
    pub fn clear_cache(&mut self) {
        self.reshuffle_cache.clear();
        self.pseudonym_rekey_cache.clear();
        self.attribute_rekey_cache.clear();
    }

    // ========================================
    // Operation verification with commitments
    // ========================================

    /// Verify a pseudonymization operation (RSK) with commitments passed directly.
    ///
    /// This is the primary verification method used by most code. It verifies that
    /// the operation was performed correctly using the provided commitments.
    #[must_use]
    pub fn verify_pseudonymization<E>(
        &self,
        original: &E,
        _result: &E,
        operation_proof: &VerifiableRSK,
        factors_proof: &RSKFactorsProof,
        commitments: &ProvedPseudonymizationCommitments,
    ) -> bool
    where
        E: ElGamalEncrypted + Pseudonymizable,
    {
        // Verify factors proof against commitments
        if !factors_proof.verify(&commitments.reshuffle_commitments, &commitments.rekey_commitments) {
            return false;
        }

        // Verify operation proof
        operation_proof
            .verified_reconstruct(
                original.value(),
                factors_proof,
                &commitments.reshuffle_commitments,
                &commitments.rekey_commitments,
            )
            .is_some()
    }

    /// Verify a pseudonym rekey operation with commitments passed directly.
    #[must_use]
    pub fn verify_pseudonym_rekey<E>(
        &self,
        original: &E,
        _result: &E,
        proof: &VerifiableRekey,
        commitments: &ProvedRekeyCommitments,
    ) -> bool
    where
        E: ElGamalEncrypted + Rekeyable,
    {
        proof
            .verified_reconstruct(original.value(), &commitments.commitments)
            .is_some()
    }

    /// Verify an attribute rekey operation with commitments passed directly.
    #[must_use]
    pub fn verify_attribute_rekey<E>(
        &self,
        original: &E,
        _result: &E,
        proof: &VerifiableRekey,
        commitments: &ProvedRekeyCommitments,
    ) -> bool
    where
        E: ElGamalEncrypted + Rekeyable,
    {
        proof
            .verified_reconstruct(original.value(), &commitments.commitments)
            .is_some()
    }

    /// Verify a complete record transcryption with commitments passed directly.
    #[must_use]
    pub fn verify_record_transcryption(
        &self,
        original: &EncryptedRecord,
        result: &EncryptedRecord,
        proof: &RecordTranscryptionProof,
        pseudonym_commitments: &ProvedPseudonymizationCommitments,
        attribute_commitments: &ProvedRekeyCommitments,
    ) -> bool {
        // Verify pseudonym factors proof
        if !proof.pseudonym_factors_proof.verify(
            &pseudonym_commitments.reshuffle_commitments,
            &pseudonym_commitments.rekey_commitments,
        ) {
            return false;
        }

        // Verify each pseudonym operation
        for ((orig_pseudo, _result_pseudo), op_proof) in original
            .pseudonyms
            .iter()
            .zip(result.pseudonyms.iter())
            .zip(proof.pseudonym_operation_proofs.iter())
        {
            if op_proof
                .verified_reconstruct(
                    orig_pseudo.value(),
                    &proof.pseudonym_factors_proof,
                    &pseudonym_commitments.reshuffle_commitments,
                    &pseudonym_commitments.rekey_commitments,
                )
                .is_none()
            {
                return false;
            }
        }

        // Verify each attribute operation
        for ((orig_attr, _result_attr), op_proof) in original
            .attributes
            .iter()
            .zip(result.attributes.iter())
            .zip(proof.attribute_operation_proofs.iter())
        {
            if op_proof
                .verified_reconstruct(orig_attr.value(), &attribute_commitments.commitments)
                .is_none()
            {
                return false;
            }
        }

        true
    }

    // ========================================
    // Operation verification using cached commitments
    // ========================================

    /// Helper: Combine rekey commitments for a transition (val from source, inv from target).
    fn combine_rekey_commitments(
        from: &ProvedRekeyCommitments,
        to: &ProvedRekeyCommitments,
    ) -> RekeyFactorCommitments {
        RekeyFactorCommitments::from(crate::core::proved::FactorCommitments {
            val: from.commitments.val,
            inv: to.commitments.inv,
        })
    }

    /// Verify a pseudonymization operation using cached commitments.
    ///
    /// This verifies a transition from domain_from→domain_to and context_from→context_to
    /// using commitments previously stored in the cache.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_pseudonymization_from_cache<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        _result: &E,
        operation_proof: &VerifiableRSK,
        factors_proof: &RSKFactorsProof,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool
    where
        E: ElGamalEncrypted + Pseudonymizable,
    {
        let transcryptor_id = transcryptor_id.to_string();

        // Retrieve commitments from cache
        let Some(reshuffle_from) = self.reshuffle_cache.retrieve(&(transcryptor_id.clone(), domain_from.clone())) else {
            return false;
        };
        let Some(reshuffle_to) = self.reshuffle_cache.retrieve(&(transcryptor_id.clone(), domain_to.clone())) else {
            return false;
        };
        let Some(rekey_from) = self.pseudonym_rekey_cache.retrieve(&(transcryptor_id.clone(), context_from.clone())) else {
            return false;
        };
        let Some(rekey_to) = self.pseudonym_rekey_cache.retrieve(&(transcryptor_id, context_to.clone())) else {
            return false;
        };

        // Construct combined commitments for the transition
        // For reshuffle: use inv from source domain, val from target domain
        let reshuffle_commitments = PseudonymizationFactorCommitments::from(
            crate::core::proved::FactorCommitments {
                inv: reshuffle_from.commitments.inv,
                val: reshuffle_to.commitments.val,
            },
        );

        // For rekey: use val from source context, inv from target context
        let rekey_commitments = Self::combine_rekey_commitments(rekey_from, rekey_to);

        // Verify the factors proof (S, K^-1, T)
        if !factors_proof.verify(&reshuffle_commitments, &rekey_commitments) {
            return false;
        }

        // Verify the operation proof
        operation_proof.verified_reconstruct(
            original.value(),
            factors_proof,
            &reshuffle_commitments,
            &rekey_commitments,
        ).is_some()
    }

    /// Verify a pseudonym rekey operation using cached commitments.
    #[must_use]
    pub fn verify_pseudonym_rekey_from_cache<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        _result: &E,
        proof: &VerifiableRekey,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool
    where
        E: ElGamalEncrypted + Rekeyable,
    {
        let transcryptor_id = transcryptor_id.to_string();

        let Some(rekey_from) = self.pseudonym_rekey_cache.retrieve(&(transcryptor_id.clone(), context_from.clone())) else {
            return false;
        };
        let Some(rekey_to) = self.pseudonym_rekey_cache.retrieve(&(transcryptor_id, context_to.clone())) else {
            return false;
        };

        let rekey_commitments = Self::combine_rekey_commitments(rekey_from, rekey_to);

        proof
            .verified_reconstruct(original.value(), &rekey_commitments)
            .is_some()
    }

    /// Verify an attribute rekey operation using cached commitments.
    #[must_use]
    pub fn verify_attribute_rekey_from_cache<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        _result: &E,
        proof: &VerifiableRekey,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool
    where
        E: ElGamalEncrypted + Rekeyable,
    {
        let transcryptor_id = transcryptor_id.to_string();

        let Some(rekey_from) = self.attribute_rekey_cache.retrieve(&(transcryptor_id.clone(), context_from.clone())) else {
            return false;
        };
        let Some(rekey_to) = self.attribute_rekey_cache.retrieve(&(transcryptor_id, context_to.clone())) else {
            return false;
        };

        let rekey_commitments = Self::combine_rekey_commitments(rekey_from, rekey_to);

        proof
            .verified_reconstruct(original.value(), &rekey_commitments)
            .is_some()
    }

    /// Verify a complete record transcryption using cached commitments.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_record_transcryption_from_cache(
        &self,
        transcryptor_id: &str,
        original: &EncryptedRecord,
        result: &EncryptedRecord,
        proof: &RecordTranscryptionProof,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool {
        let transcryptor_id = transcryptor_id.to_string();

        // Retrieve commitments from cache
        let Some(reshuffle_from) = self.reshuffle_cache.retrieve(&(transcryptor_id.clone(), domain_from.clone())) else {
            return false;
        };
        let Some(reshuffle_to) = self.reshuffle_cache.retrieve(&(transcryptor_id.clone(), domain_to.clone())) else {
            return false;
        };
        let Some(pseudonym_rekey_from) = self.pseudonym_rekey_cache.retrieve(&(transcryptor_id.clone(), context_from.clone())) else {
            return false;
        };
        let Some(pseudonym_rekey_to) = self.pseudonym_rekey_cache.retrieve(&(transcryptor_id.clone(), context_to.clone())) else {
            return false;
        };
        let Some(attribute_rekey_from) = self.attribute_rekey_cache.retrieve(&(transcryptor_id.clone(), context_from.clone())) else {
            return false;
        };
        let Some(attribute_rekey_to) = self.attribute_rekey_cache.retrieve(&(transcryptor_id, context_to.clone())) else {
            return false;
        };

        // Construct combined commitments for pseudonym operations
        let reshuffle_commitments = PseudonymizationFactorCommitments::from(
            crate::core::proved::FactorCommitments {
                inv: reshuffle_from.commitments.inv,
                val: reshuffle_to.commitments.val,
            },
        );
        let pseudonym_rekey_commitments = Self::combine_rekey_commitments(pseudonym_rekey_from, pseudonym_rekey_to);

        // Verify pseudonym factors proof
        if !proof
            .pseudonym_factors_proof
            .verify(&reshuffle_commitments, &pseudonym_rekey_commitments)
        {
            return false;
        }

        // Verify each pseudonym operation
        for ((orig_pseudo, _result_pseudo), op_proof) in original
            .pseudonyms
            .iter()
            .zip(result.pseudonyms.iter())
            .zip(proof.pseudonym_operation_proofs.iter())
        {
            if op_proof
                .verified_reconstruct(
                    orig_pseudo.value(),
                    &proof.pseudonym_factors_proof,
                    &reshuffle_commitments,
                    &pseudonym_rekey_commitments,
                )
                .is_none()
            {
                return false;
            }
        }

        // Construct combined commitments for attribute operations
        let attribute_rekey_commitments = Self::combine_rekey_commitments(attribute_rekey_from, attribute_rekey_to);

        // Verify each attribute operation
        for ((orig_attr, _result_attr), op_proof) in original
            .attributes
            .iter()
            .zip(result.attributes.iter())
            .zip(proof.attribute_operation_proofs.iter())
        {
            if op_proof
                .verified_reconstruct(orig_attr.value(), &attribute_rekey_commitments)
                .is_none()
            {
                return false;
            }
        }

        true
    }

    /// Verify long pseudonym pseudonymization with commitments.
    #[must_use]
    pub fn verify_pseudonymization_long(
        &self,
        originals: &[EncryptedPseudonym],
        results: &[EncryptedPseudonym],
        operation_proofs: &[VerifiableRSK],
        factors_proof: &RSKFactorsProof,
        commitments: &ProvedPseudonymizationCommitments,
    ) -> bool {
        // Verify factors proof
        if !factors_proof.verify(&commitments.reshuffle_commitments, &commitments.rekey_commitments) {
            return false;
        }

        // Verify each block
        for ((orig, _result), op_proof) in originals
            .iter()
            .zip(results.iter())
            .zip(operation_proofs.iter())
        {
            if op_proof
                .verified_reconstruct(
                    orig.value(),
                    factors_proof,
                    &commitments.reshuffle_commitments,
                    &commitments.rekey_commitments,
                )
                .is_none()
            {
                return false;
            }
        }

        true
    }

    /// Verify pseudonymization using cached commitments (convenience method).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_pseudonymization_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        result: &E,
        operation_proof: &VerifiableRSK,
        factors_proof: &RSKFactorsProof,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> bool
    where
        E: ElGamalEncrypted + Pseudonymizable,
    {
        self.verify_pseudonymization_from_cache(
            transcryptor_id,
            original,
            result,
            operation_proof,
            factors_proof,
            domain_from,
            domain_to,
            context_from,
            context_to,
        )
    }
}

/// Read-only view of the verifier's cache.
pub struct VerifierCache<'a> {
    reshuffle: &'a ReshuffleCommitmentsCache,
    pseudonym_rekey: &'a PseudonymRekeyCommitmentsCache,
    attribute_rekey: &'a AttributeRekeyCommitmentsCache,
}

impl<'a> VerifierCache<'a> {
    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.reshuffle.is_empty()
            && self.pseudonym_rekey.is_empty()
            && self.attribute_rekey.is_empty()
    }

    /// Get total count of cached commitments.
    pub fn total_count(&self) -> usize {
        self.reshuffle.len() + self.pseudonym_rekey.len() + self.attribute_rekey.len()
    }

    /// Get count of cached pseudonymization commitments.
    pub fn pseudonymization_count(&self) -> usize {
        self.reshuffle.len() + self.pseudonym_rekey.len()
    }

    /// Get count of cached reshuffle commitments.
    pub fn reshuffle_count(&self) -> usize {
        self.reshuffle.len()
    }

    /// Get count of cached pseudonym rekey commitments.
    pub fn pseudonym_rekey_count(&self) -> usize {
        self.pseudonym_rekey.len()
    }

    /// Get count of cached attribute rekey commitments.
    pub fn attribute_rekey_count(&self) -> usize {
        self.attribute_rekey.len()
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}
