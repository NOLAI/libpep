//! WASM bindings for the verifier.

use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::commitments::{
    WASMProvedPseudonymizationCommitments, WASMProvedRekeyCommitments,
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

    /// Verify pseudonymization commitments.
    #[wasm_bindgen(js_name = verifyPseudonymizationCommitments)]
    pub fn verify_pseudonymization_commitments(
        &self,
        commitments: &WASMProvedPseudonymizationCommitments,
    ) -> bool {
        self.inner
            .verify_pseudonymization_commitments(&commitments.0)
    }

    /// Verify rekey commitments.
    #[wasm_bindgen(js_name = verifyRekeyCommitments)]
    pub fn verify_rekey_commitments(&self, commitments: &WASMProvedRekeyCommitments) -> bool {
        self.inner.verify_rekey_commitments(&commitments.0)
    }

    /// Register pseudonymization commitments for caching.
    #[wasm_bindgen(js_name = registerPseudonymizationCommitments)]
    pub fn register_pseudonymization_commitments(
        &mut self,
        transcryptor_id: &str,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
        commitments: &WASMProvedPseudonymizationCommitments,
    ) {
        self.inner.register_pseudonymization_commitments(
            &transcryptor_id.to_string(),
            &domain_from.0,
            &domain_to.0,
            &context_from.0,
            &context_to.0,
            commitments.0,
        );
    }

    /// Register attribute rekey commitments for caching.
    #[wasm_bindgen(js_name = registerAttributeRekeyCommitments)]
    pub fn register_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: &str,
        context_from: &WASMEncryptionContext,
        context_to: &WASMEncryptionContext,
        commitments: &WASMProvedRekeyCommitments,
    ) {
        self.inner.register_attribute_rekey_commitments(
            &transcryptor_id.to_string(),
            &context_from.0,
            &context_to.0,
            commitments.0,
        );
    }

    /// Check if reshuffle commitments exist in cache.
    #[wasm_bindgen(js_name = hasReshuffleCommitments)]
    pub fn has_reshuffle_commitments(
        &self,
        transcryptor_id: &str,
        domain: &WASMPseudonymizationDomain,
    ) -> bool {
        self.inner
            .has_reshuffle_commitments(transcryptor_id, &domain.0)
    }

    /// Check if pseudonym rekey commitments exist in cache.
    #[wasm_bindgen(js_name = hasPseudonymRekeyCommitments)]
    pub fn has_pseudonym_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context: &WASMEncryptionContext,
    ) -> bool {
        self.inner
            .has_pseudonym_rekey_commitments(transcryptor_id, &context.0)
    }

    /// Check if attribute rekey commitments exist in cache.
    #[wasm_bindgen(js_name = hasAttributeRekeyCommitments)]
    pub fn has_attribute_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context: &WASMEncryptionContext,
    ) -> bool {
        self.inner
            .has_attribute_rekey_commitments(transcryptor_id, &context.0)
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

    /// Verify a pseudonymization operation with commitments.
    ///
    /// Note: Proofs must be passed as JSON strings (due to WASM limitations).
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyPseudonymization)]
    pub fn verify_pseudonymization(
        &self,
        original: &WASMEncryptedPseudonym,
        result: &WASMEncryptedPseudonym,
        operation_proof_json: &str,
        factors_proof_json: &str,
        commitments: &WASMProvedPseudonymizationCommitments,
    ) -> Result<bool, JsValue> {
        use crate::core::proved::{RSKFactorsProof, VerifiableRSK};

        let operation_proof: VerifiableRSK = serde_json::from_str(operation_proof_json)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        let factors_proof: RSKFactorsProof = serde_json::from_str(factors_proof_json)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

        Ok(self.inner.verify_pseudonymization(
            &original.0,
            &result.0,
            &operation_proof,
            &factors_proof,
            &commitments.0,
        ))
    }

    /// Verify a pseudonym rekey operation with commitments.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyPseudonymRekey)]
    pub fn verify_pseudonym_rekey(
        &self,
        original: &WASMEncryptedPseudonym,
        result: &WASMEncryptedPseudonym,
        proof_json: &str,
        commitments: &WASMProvedRekeyCommitments,
    ) -> Result<bool, JsValue> {
        use crate::core::proved::VerifiableRekey;

        let proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(|e| JsValue::from_str(&format!("{}", e)))?;

        Ok(self
            .inner
            .verify_pseudonym_rekey(&original.0, &result.0, &proof, &commitments.0))
    }

    /// Verify an attribute rekey operation with commitments.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyAttributeRekey)]
    pub fn verify_attribute_rekey(
        &self,
        original: &WASMEncryptedAttribute,
        result: &WASMEncryptedAttribute,
        proof_json: &str,
        commitments: &WASMProvedRekeyCommitments,
    ) -> Result<bool, JsValue> {
        use crate::core::proved::VerifiableRekey;

        let proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(|e| JsValue::from_str(&format!("{}", e)))?;

        Ok(self
            .inner
            .verify_attribute_rekey(&original.0, &result.0, &proof, &commitments.0))
    }
}

impl Default for WASMVerifier {
    fn default() -> Self {
        Self::new()
    }
}
