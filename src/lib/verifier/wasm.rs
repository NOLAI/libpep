//! WASM bindings for the verifier.

use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::commitments::{
    WASMVerifiablePseudonymizationCommitment, WASMVerifiableRekeyCommitment,
    WASMVerifiableTranscryptionCommitment,
};
use crate::factors::wasm::contexts::{WASMEncryptionContext, WASMPseudonymizationDomain};
use crate::verifier::Verifier;
use wasm_bindgen::prelude::*;

/// A verifier for verifiable transcryption operations (WASM).
#[wasm_bindgen(js_name = Verifier)]
pub struct WASMVerifier {
    pub(crate) inner: Verifier,
}

#[wasm_bindgen(js_class = Verifier)]
impl WASMVerifier {
    /// Create a new verifier with empty caches.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Verifier::new(),
        }
    }

    /// Create a new verifier with empty caches, each capped at
    /// `maxEntries` commitments. Once full,
    /// `register*Commitments` rejects with a typed cache-full error.
    #[wasm_bindgen(js_name = withCacheCapacity)]
    pub fn with_cache_capacity(max_entries: usize) -> Self {
        Self {
            inner: Verifier::with_cache_capacity(max_entries),
        }
    }

    /// Register pseudonymization commitments for a transition.
    #[wasm_bindgen(js_name = registerPseudonymizationCommitments)]
    pub fn register_pseudonymization_commitments(
        &mut self,
        transcryptor_id: &str,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<(), JsValue> {
        self.inner
            .register_pseudonymization_commitments(
                &transcryptor_id.to_string(),
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
                commitments.0,
            )
            .map_err(crate::wasm_errors::register_commitments_err_to_js)
    }

    /// Register attribute rekey commitments for a transition.
    #[wasm_bindgen(js_name = registerAttributeRekeyCommitments)]
    pub fn register_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: &str,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<(), JsValue> {
        self.inner
            .register_attribute_rekey_commitments(
                &transcryptor_id.to_string(),
                &context_from.0,
                &context_to.0,
                commitments.0,
            )
            .map_err(crate::wasm_errors::register_commitments_err_to_js)
    }

    /// Register pseudonym rekey commitments for a transition.
    #[wasm_bindgen(js_name = registerPseudonymRekeyCommitments)]
    pub fn register_pseudonym_rekey_commitments(
        &mut self,
        transcryptor_id: &str,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<(), JsValue> {
        self.inner
            .register_pseudonym_rekey_commitments(
                &transcryptor_id.to_string(),
                &context_from.0,
                &context_to.0,
                commitments.0,
            )
            .map_err(crate::wasm_errors::register_commitments_err_to_js)
    }

    /// Check if pseudonymization commitments exist for a transition.
    #[wasm_bindgen(js_name = hasPseudonymizationCommitments)]
    pub fn has_pseudonymization_commitments(
        &self,
        transcryptor_id: &str,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> bool {
        self.inner.has_pseudonymization_commitments(
            transcryptor_id,
            &domain_from.0,
            &domain_to.0,
            &context_from.0,
            &context_to.0,
        )
    }

    /// Check if pseudonym rekey commitments exist for a transition.
    #[wasm_bindgen(js_name = hasPseudonymRekeyCommitments)]
    pub fn has_pseudonym_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> bool {
        self.inner
            .has_pseudonym_rekey_commitments(transcryptor_id, &context_from.0, &context_to.0)
    }

    /// Check if attribute rekey commitments exist for a transition.
    #[wasm_bindgen(js_name = hasAttributeRekeyCommitments)]
    pub fn has_attribute_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> bool {
        self.inner
            .has_attribute_rekey_commitments(transcryptor_id, &context_from.0, &context_to.0)
    }

    /// Clear all cached commitments.
    #[wasm_bindgen(js_name = clearCache)]
    pub fn clear_cache(&mut self) {
        self.inner.clear_cache();
    }

    /// Get cache size.
    #[wasm_bindgen(js_name = cacheSize)]
    pub fn cache_size(&self) -> usize {
        self.inner.cache().total_count()
    }

    /// Verify a pseudonymization operation against the combined commitments,
    /// returning the reconstructed pseudonym on success or throwing on
    /// failure.
    ///
    /// The proof is passed as a JSON string due to WASM limitations.
    #[cfg(all(feature = "serde", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyPseudonymization)]
    pub fn verify_pseudonymization(
        &self,
        original: &WASMEncryptedPseudonym,
        operation_proof_json: &str,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMEncryptedPseudonym, JsValue> {
        use crate::core::verifiable::VerifiableRRSK;

        let core_proof: VerifiableRRSK = serde_json::from_str(operation_proof_json)
            .map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);

        self.inner
            .verified_reconstruct_pseudonymization(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedPseudonym)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Verify a pseudonymization operation against the combined commitments,
    /// returning the reconstructed pseudonym on success. In non-elgamal3
    /// builds the recipient public key the original ciphertext was encrypted
    /// under must be supplied.
    #[cfg(all(feature = "serde", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = verifyPseudonymization)]
    pub fn verify_pseudonymization(
        &self,
        original: &WASMEncryptedPseudonym,
        operation_proof_json: &str,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMEncryptedPseudonym, JsValue> {
        use crate::core::verifiable::VerifiableRRSK;

        let core_proof: VerifiableRRSK = serde_json::from_str(operation_proof_json)
            .map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);

        self.inner
            .verified_reconstruct_pseudonymization(&original.0, &proof, &pk, &commitments.0)
            .map(WASMEncryptedPseudonym)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Verify a pseudonym rekey operation, returning the reconstructed
    /// pseudonym on success.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyPseudonymRekey)]
    pub fn verify_pseudonym_rekey(
        &self,
        original: &WASMEncryptedPseudonym,
        proof_json: &str,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMEncryptedPseudonym, JsValue> {
        use crate::core::verifiable::VerifiableRekey;

        let core_proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::PseudonymRekeyProof(core_proof);

        self.inner
            .verified_reconstruct_rekey(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedPseudonym)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Verify an attribute rekey operation, returning the reconstructed
    /// attribute on success.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyAttributeRekey)]
    pub fn verify_attribute_rekey(
        &self,
        original: &WASMEncryptedAttribute,
        proof_json: &str,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMEncryptedAttribute, JsValue> {
        use crate::core::verifiable::VerifiableRekey;

        let core_proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::AttributeRekeyProof(core_proof);

        self.inner
            .verified_reconstruct_rekey(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedAttribute)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Verify a record transcryption operation, returning the reconstructed
    /// record on success.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifyRecordTranscryption)]
    pub fn verify_record_transcryption(
        &self,
        original: &crate::data::wasm::records::WASMEncryptedRecord,
        proof: &crate::data::wasm::records::WASMRecordTranscryptionProof,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::records::WASMEncryptedRecord, JsValue> {
        let orig: crate::data::records::EncryptedRecord = original.clone().into();
        self.inner
            .verified_reconstruct_transcryption(&orig, &proof.0, &commitments.0)
            .map(crate::data::wasm::records::WASMEncryptedRecord::from)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyRecordTranscryption)]
    pub fn verify_record_transcryption(
        &self,
        original: &crate::data::wasm::records::WASMEncryptedRecord,
        proof: &crate::data::wasm::records::WASMRecordTranscryptionProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::records::WASMEncryptedRecord, JsValue> {
        let orig: crate::data::records::EncryptedRecord = original.clone().into();
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .verified_reconstruct_transcryption(&orig, &proof.0, &sk, &commitments.0)
            .map(crate::data::wasm::records::WASMEncryptedRecord::from)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Verify a long record transcryption operation, returning the
    /// reconstructed long record on success.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyLongRecordTranscryption)]
    pub fn verify_long_record_transcryption(
        &self,
        original: &crate::data::wasm::records::WASMLongEncryptedRecord,
        proof: &crate::data::wasm::records::WASMLongRecordTranscryptionProof,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::records::WASMLongEncryptedRecord, JsValue> {
        let orig: crate::data::records::LongEncryptedRecord = original.clone().into();
        self.inner
            .verified_reconstruct_transcryption(&orig, &proof.0, &commitments.0)
            .map(crate::data::wasm::records::WASMLongEncryptedRecord::from)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = verifyLongRecordTranscryption)]
    pub fn verify_long_record_transcryption(
        &self,
        original: &crate::data::wasm::records::WASMLongEncryptedRecord,
        proof: &crate::data::wasm::records::WASMLongRecordTranscryptionProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::records::WASMLongEncryptedRecord, JsValue> {
        let orig: crate::data::records::LongEncryptedRecord = original.clone().into();
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .verified_reconstruct_transcryption(&orig, &proof.0, &sk, &commitments.0)
            .map(crate::data::wasm::records::WASMLongEncryptedRecord::from)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Cache-backed pseudonymization verification.
    #[cfg(all(feature = "serde", feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = verifyPseudonymizationCached)]
    pub fn verify_pseudonymization_cached(
        &self,
        transcryptor_id: &str,
        original: &WASMEncryptedPseudonym,
        operation_proof_json: &str,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> Result<WASMEncryptedPseudonym, JsValue> {
        use crate::core::verifiable::VerifiableRRSK;
        let core_proof: VerifiableRRSK = serde_json::from_str(operation_proof_json)
            .map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);
        self.inner
            .verified_reconstruct_pseudonymization_cached(
                transcryptor_id,
                &original.0,
                &proof,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(WASMEncryptedPseudonym)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    #[cfg(all(feature = "serde", not(feature = "elgamal3")))]
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = verifyPseudonymizationCached)]
    pub fn verify_pseudonymization_cached(
        &self,
        transcryptor_id: &str,
        original: &WASMEncryptedPseudonym,
        operation_proof_json: &str,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> Result<WASMEncryptedPseudonym, JsValue> {
        use crate::core::verifiable::VerifiableRRSK;
        let core_proof: VerifiableRRSK = serde_json::from_str(operation_proof_json)
            .map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.inner
            .verified_reconstruct_pseudonymization_cached(
                transcryptor_id,
                &original.0,
                &proof,
                &pk,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(WASMEncryptedPseudonym)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Cache-backed pseudonym rekey verification.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyPseudonymRekeyCached)]
    pub fn verify_pseudonym_rekey_cached(
        &self,
        transcryptor_id: &str,
        original: &WASMEncryptedPseudonym,
        proof_json: &str,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> Result<WASMEncryptedPseudonym, JsValue> {
        use crate::core::verifiable::VerifiableRekey;
        let core_proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::PseudonymRekeyProof(core_proof);
        self.inner
            .verified_reconstruct_pseudonym_rekey_cached(
                transcryptor_id,
                &original.0,
                &proof,
                &context_from.0,
                &context_to.0,
            )
            .map(WASMEncryptedPseudonym)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Cache-backed attribute rekey verification.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyAttributeRekeyCached)]
    pub fn verify_attribute_rekey_cached(
        &self,
        transcryptor_id: &str,
        original: &WASMEncryptedAttribute,
        proof_json: &str,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> Result<WASMEncryptedAttribute, JsValue> {
        use crate::core::verifiable::VerifiableRekey;
        let core_proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(crate::wasm_errors::malformed_proof_err)?;
        let proof = crate::data::verifiable::simple::AttributeRekeyProof(core_proof);
        self.inner
            .verified_reconstruct_attribute_rekey_cached(
                transcryptor_id,
                &original.0,
                &proof,
                &context_from.0,
                &context_to.0,
            )
            .map(WASMEncryptedAttribute)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }
}

impl Default for WASMVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Verifiable-derivation methods (master keys, blinding commitments, session-
// key-share verification, cached transcryption).
// ---------------------------------------------------------------------------
#[cfg(feature = "verifiable-derivation")]
#[wasm_bindgen(js_class = Verifier)]
impl WASMVerifier {
    /// Register blinding commitments for a transcryptor.
    #[wasm_bindgen(js_name = registerBlindingCommitments)]
    pub fn register_blinding_commitments(
        &mut self,
        transcryptor_id: &str,
        commitments: &crate::keys::wasm::distribution::proofs::WASMBlindingCommitments,
    ) -> Result<(), JsValue> {
        self.inner
            .register_blinding_commitments(transcryptor_id.to_string(), commitments.0)
            .map_err(crate::wasm_errors::register_commitments_err_to_js)
    }

    /// Check if blinding commitments are registered for a transcryptor.
    #[wasm_bindgen(js_name = hasBlindingCommitments)]
    pub fn has_blinding_commitments(&self, transcryptor_id: &str) -> bool {
        self.inner.has_blinding_commitments(transcryptor_id)
    }

    /// Retrieve the blinding commitments for a transcryptor.
    #[wasm_bindgen(js_name = getBlindingCommitments)]
    pub fn get_blinding_commitments(
        &self,
        transcryptor_id: &str,
    ) -> Option<crate::keys::wasm::distribution::proofs::WASMBlindingCommitments> {
        self.inner
            .get_blinding_commitments(transcryptor_id)
            .copied()
            .map(crate::keys::wasm::distribution::proofs::WASMBlindingCommitments)
    }

    /// Register master pseudonymization and rekeying public keys for a transcryptor.
    #[wasm_bindgen(js_name = registerMasterKeys)]
    pub fn register_master_keys(
        &mut self,
        transcryptor_id: &str,
        pseudonym_master_key: &crate::factors::wasm::verifiable::WASMMasterPseudonymizationPublicKey,
        rekey_master_key: &crate::factors::wasm::verifiable::WASMMasterRekeyingPublicKey,
    ) -> Result<(), JsValue> {
        self.inner
            .register_master_keys(
                transcryptor_id.to_string(),
                pseudonym_master_key.0,
                rekey_master_key.0,
            )
            .map_err(crate::wasm_errors::register_commitments_err_to_js)
    }

    /// Check if master keys are registered for a transcryptor.
    #[wasm_bindgen(js_name = hasMasterKeys)]
    pub fn has_master_keys(&self, transcryptor_id: &str) -> bool {
        self.inner.has_master_keys(transcryptor_id)
    }

    /// Retrieve the master pseudonymization public key for a transcryptor.
    #[wasm_bindgen(js_name = getMasterPseudonymKey)]
    pub fn get_master_pseudonym_key(
        &self,
        transcryptor_id: &str,
    ) -> Option<crate::factors::wasm::verifiable::WASMMasterPseudonymizationPublicKey> {
        self.inner
            .get_master_pseudonym_key(transcryptor_id)
            .copied()
            .map(crate::factors::wasm::verifiable::WASMMasterPseudonymizationPublicKey)
    }

    /// Retrieve the master rekeying public key for a transcryptor.
    #[wasm_bindgen(js_name = getMasterRekeyKey)]
    pub fn get_master_rekey_key(
        &self,
        transcryptor_id: &str,
    ) -> Option<crate::factors::wasm::verifiable::WASMMasterRekeyingPublicKey> {
        self.inner
            .get_master_rekey_key(transcryptor_id)
            .copied()
            .map(crate::factors::wasm::verifiable::WASMMasterRekeyingPublicKey)
    }

    /// Verify a session-key-share proof against a stored blinding commitment.
    #[wasm_bindgen(js_name = verifySessionKeyShareWithCommitment)]
    pub fn verify_session_key_share_with_commitment(
        &self,
        transcryptor_id: &str,
        rekey_commitment: &crate::arithmetic::wasm::group_elements::WASMGroupElement,
        for_pseudonym: bool,
        proof: &crate::keys::wasm::distribution::proofs::WASMSessionKeyShareProof,
    ) -> Result<(), JsValue> {
        self.inner
            .verify_session_key_share_with_commitment(
                transcryptor_id,
                &rekey_commitment.0,
                for_pseudonym,
                &proof.0,
            )
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Cache-backed record transcryption verification (elgamal3 build).
    #[cfg(feature = "elgamal3")]
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = verifyRecordTranscryptionCached)]
    pub fn verify_record_transcryption_cached(
        &self,
        transcryptor_id: &str,
        original: &crate::data::wasm::records::WASMEncryptedRecord,
        proof: &crate::data::wasm::records::WASMRecordTranscryptionProof,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> Result<crate::data::wasm::records::WASMEncryptedRecord, JsValue> {
        let orig: crate::data::records::EncryptedRecord = original.clone().into();
        self.inner
            .verified_reconstruct_transcryption_cached(
                transcryptor_id,
                &orig,
                &proof.0,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(crate::data::wasm::records::WASMEncryptedRecord::from)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    /// Cache-backed record transcryption verification (non-elgamal3 build).
    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = verifyRecordTranscryptionCached)]
    pub fn verify_record_transcryption_cached(
        &self,
        transcryptor_id: &str,
        original: &crate::data::wasm::records::WASMEncryptedRecord,
        proof: &crate::data::wasm::records::WASMRecordTranscryptionProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
    ) -> Result<crate::data::wasm::records::WASMEncryptedRecord, JsValue> {
        let orig: crate::data::records::EncryptedRecord = original.clone().into();
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .verified_reconstruct_transcryption_cached(
                transcryptor_id,
                &orig,
                &proof.0,
                &sk,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(crate::data::wasm::records::WASMEncryptedRecord::from)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }
}

// ---------------------------------------------------------------------------
// Batch-proof verification methods
//
// Mirrors the per-message `verify*` methods above but operates on
// `EncryptedBatch<E>` (wrapped as `WASM*Batch`) and the corresponding hoisted
// batch proof. Cfg layout matches the inherent
// `*BatchProof::verified_reconstruct_batch` impls in
// `crate::data::verifiable`.
// ---------------------------------------------------------------------------
#[cfg(all(feature = "batch", feature = "verifiable"))]
#[wasm_bindgen(js_class = Verifier)]
impl WASMVerifier {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyPseudonymizationBatch)]
    pub fn verify_pseudonymization_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifyPseudonymizationBatch)]
    pub fn verify_pseudonymization_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifyPseudonymizationBatch)]
    pub fn verify_pseudonymization_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMPseudonymPseudonymizationBatchProof,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedPseudonymBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyPseudonymRekeyBatch)]
    pub fn verify_pseudonym_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMPseudonymRekeyBatchProof,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedPseudonymBatch, JsValue> {
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifyPseudonymRekeyBatch)]
    pub fn verify_pseudonym_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMPseudonymRekeyBatchProof,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedPseudonymBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyAttributeRekeyBatch)]
    pub fn verify_attribute_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedAttributeBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMAttributeRekeyBatchProof,
        new_public_key: &crate::keys::wasm::types::WASMAttributeSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedAttributeBatch, JsValue> {
        let new_pk = crate::keys::AttributeSessionPublicKey::from(new_public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedAttributeBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifyAttributeRekeyBatch)]
    pub fn verify_attribute_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedAttributeBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMAttributeRekeyBatchProof,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedAttributeBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedAttributeBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyLongPseudonymizationBatch)]
    pub fn verify_long_pseudonymization_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifyLongPseudonymizationBatch)]
    pub fn verify_long_pseudonymization_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyLongPseudonymizationBatch)]
    pub fn verify_long_pseudonymization_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongPseudonymPseudonymizationBatchProof,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyLongPseudonymRekeyBatch)]
    pub fn verify_long_pseudonym_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongPseudonymRekeyBatchProof,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch, JsValue> {
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", any(feature = "elgamal3", not(feature = "batch-pk"))))]
    #[wasm_bindgen(js_name = verifyLongPseudonymRekeyBatch)]
    pub fn verify_long_pseudonym_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongPseudonymRekeyBatchProof,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyLongAttributeRekeyBatch)]
    pub fn verify_long_attribute_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedAttributeBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongAttributeRekeyBatchProof,
        new_public_key: &crate::keys::wasm::types::WASMAttributeSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedAttributeBatch, JsValue> {
        let new_pk = crate::keys::AttributeSessionPublicKey::from(new_public_key.0 .0);
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedAttributeBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", any(feature = "elgamal3", not(feature = "batch-pk"))))]
    #[wasm_bindgen(js_name = verifyLongAttributeRekeyBatch)]
    pub fn verify_long_attribute_rekey_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedAttributeBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongAttributeRekeyBatchProof,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedAttributeBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedAttributeBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyRecordTranscryptionBatch)]
    pub fn verify_record_transcryption_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedRecordBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMRecordTranscryptionBatchProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        new_session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        let new_sk: crate::keys::SessionKeys = (*new_session_keys).into();
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedRecordBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifyRecordTranscryptionBatch)]
    pub fn verify_record_transcryption_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedRecordBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMRecordTranscryptionBatchProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedRecordBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifyRecordTranscryptionBatch)]
    pub fn verify_record_transcryption_batch(
        &self,
        original: &crate::data::wasm::batch::WASMEncryptedRecordBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMRecordTranscryptionBatchProof,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::batch::WASMEncryptedRecordBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMEncryptedRecordBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifyLongRecordTranscryptionBatch)]
    pub fn verify_long_record_transcryption_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedRecordBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongRecordTranscryptionBatchProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        new_session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        let new_sk: crate::keys::SessionKeys = (*new_session_keys).into();
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedRecordBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifyLongRecordTranscryptionBatch)]
    pub fn verify_long_record_transcryption_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedRecordBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongRecordTranscryptionBatchProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedRecordBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyLongRecordTranscryptionBatch)]
    pub fn verify_long_record_transcryption_batch(
        &self,
        original: &crate::data::wasm::batch::WASMLongEncryptedRecordBatch,
        proof: &crate::data::wasm::verifiable_batch::WASMLongRecordTranscryptionBatchProof,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<crate::data::wasm::batch::WASMLongEncryptedRecordBatch, JsValue> {
        proof
            .0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| crate::data::wasm::batch::WASMLongEncryptedRecordBatch { inner })
            .ok_or_else(|| {
                crate::wasm_errors::verify_err_to_js(crate::verifier::VerifyError::ProofRejected)
            })
    }
}
