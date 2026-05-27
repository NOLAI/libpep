//! WASM bindings for the verifier.

use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::commitments::{
    WASMVerifiablePseudonymizationCommitments, WASMVerifiableRekeyCommitments,
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
        commitments: &WASMVerifiablePseudonymizationCommitments,
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
        commitments: &WASMVerifiableRekeyCommitments,
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
        commitments: &WASMVerifiableRekeyCommitments,
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
    /// returning the reconstructed pseudonym on success or `null` on
    /// failure.
    ///
    /// The proof is passed as a JSON string due to WASM limitations.
    #[cfg(all(feature = "serde", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyPseudonymization)]
    pub fn verify_pseudonymization(
        &self,
        original: &WASMEncryptedPseudonym,
        operation_proof_json: &str,
        commitments: &WASMVerifiablePseudonymizationCommitments,
    ) -> Result<Option<WASMEncryptedPseudonym>, JsValue> {
        use crate::core::verifiable::VerifiableRRSK;

        let core_proof: VerifiableRRSK = serde_json::from_str(operation_proof_json)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);

        Ok(self
            .inner
            .verified_reconstruct_pseudonymization(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedPseudonym))
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
        commitments: &WASMVerifiablePseudonymizationCommitments,
    ) -> Result<Option<WASMEncryptedPseudonym>, JsValue> {
        use crate::core::verifiable::VerifiableRRSK;

        let core_proof: VerifiableRRSK = serde_json::from_str(operation_proof_json)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        let proof = crate::data::verifiable::simple::PseudonymPseudonymizationProof(core_proof);
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);

        Ok(self
            .inner
            .verified_reconstruct_pseudonymization(&original.0, &proof, &pk, &commitments.0)
            .map(WASMEncryptedPseudonym))
    }

    /// Verify a pseudonym rekey operation, returning the reconstructed
    /// pseudonym on success.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyPseudonymRekey)]
    pub fn verify_pseudonym_rekey(
        &self,
        original: &WASMEncryptedPseudonym,
        proof_json: &str,
        commitments: &WASMVerifiableRekeyCommitments,
    ) -> Result<Option<WASMEncryptedPseudonym>, JsValue> {
        use crate::core::verifiable::VerifiableRekey;

        let core_proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        let proof = crate::data::verifiable::simple::PseudonymRekeyProof(core_proof);

        Ok(self
            .inner
            .verified_reconstruct_rekey(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedPseudonym))
    }

    /// Verify an attribute rekey operation, returning the reconstructed
    /// attribute on success.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifyAttributeRekey)]
    pub fn verify_attribute_rekey(
        &self,
        original: &WASMEncryptedAttribute,
        proof_json: &str,
        commitments: &WASMVerifiableRekeyCommitments,
    ) -> Result<Option<WASMEncryptedAttribute>, JsValue> {
        use crate::core::verifiable::VerifiableRekey;

        let core_proof: VerifiableRekey =
            serde_json::from_str(proof_json).map_err(|e| JsValue::from_str(&format!("{}", e)))?;
        let proof = crate::data::verifiable::simple::AttributeRekeyProof(core_proof);

        Ok(self
            .inner
            .verified_reconstruct_rekey(&original.0, &proof, &commitments.0)
            .map(WASMEncryptedAttribute))
    }
}

impl Default for WASMVerifier {
    fn default() -> Self {
        Self::new()
    }
}
