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
    inner: Verifier,
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
            .map_err(|e| JsValue::from_str(&e.to_string()))
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
            .map_err(|e| JsValue::from_str(&e.to_string()))
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
            .map_err(|e| JsValue::from_str(&e.to_string()))
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
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);

        self.inner
            .verified_reconstruct_pseudonymization(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedPseudonym)
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
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
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);

        self.inner
            .verified_reconstruct_pseudonymization(&original.0, &proof, &pk, &commitments.0)
            .map(WASMEncryptedPseudonym)
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
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

        let core_proof: VerifiableRekey = serde_json::from_str(proof_json)
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
        let proof = crate::data::verifiable::simple::PseudonymRekeyProof(core_proof);

        self.inner
            .verified_reconstruct_rekey(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedPseudonym)
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
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

        let core_proof: VerifiableRekey = serde_json::from_str(proof_json)
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
        let proof = crate::data::verifiable::simple::AttributeRekeyProof(core_proof);

        self.inner
            .verified_reconstruct_rekey(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedAttribute)
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
    }

    /// Verify a record transcryption operation. Takes the encrypted record and
    /// the record-transcryption proof as JSON; returns the reconstructed
    /// record JSON on success.
    #[cfg(all(feature = "serde", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyRecordTranscryption)]
    pub fn verify_record_transcryption(
        &self,
        original_json: &str,
        proof_json: &str,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<String, JsValue> {
        let original: crate::data::records::EncryptedRecord =
            serde_json::from_str(original_json)
                .map_err(|e| JsValue::from(JsError::new(&format!("original: {}", e))))?;
        let proof: crate::data::verifiable::records::RecordTranscryptionProof =
            serde_json::from_str(proof_json)
                .map_err(|e| JsValue::from(JsError::new(&format!("proof: {}", e))))?;
        let reconstructed = self
            .inner
            .verified_reconstruct_transcryption(&original, &proof, &commitments.0)
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))?;
        serde_json::to_string(&reconstructed)
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))
    }

    #[cfg(all(feature = "serde", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = verifyRecordTranscryption)]
    pub fn verify_record_transcryption(
        &self,
        original_json: &str,
        proof_json: &str,
        session_keys_json: &str,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<String, JsValue> {
        let original: crate::data::records::EncryptedRecord =
            serde_json::from_str(original_json)
                .map_err(|e| JsValue::from(JsError::new(&format!("original: {}", e))))?;
        let proof: crate::data::verifiable::records::RecordTranscryptionProof =
            serde_json::from_str(proof_json)
                .map_err(|e| JsValue::from(JsError::new(&format!("proof: {}", e))))?;
        let sk: crate::keys::SessionKeys = serde_json::from_str(session_keys_json)
            .map_err(|e| JsValue::from(JsError::new(&format!("session_keys: {}", e))))?;
        let reconstructed = self
            .inner
            .verified_reconstruct_transcryption(&original, &proof, &sk, &commitments.0)
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))?;
        serde_json::to_string(&reconstructed)
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))
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
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
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
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
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
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
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
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
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
        let core_proof: VerifiableRekey = serde_json::from_str(proof_json)
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
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
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
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
        let core_proof: VerifiableRekey = serde_json::from_str(proof_json)
            .map_err(|e| JsValue::from(JsError::new(&format!("{}", e))))?;
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
            .map_err(|e| JsValue::from(JsError::new(&e.to_string())))
    }
}

impl Default for WASMVerifier {
    fn default() -> Self {
        Self::new()
    }
}
