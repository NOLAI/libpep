//! WASM bindings for verifiable transcryptor operations.

use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::commitments::{
    WASMVerifiablePseudonymizationCommitments, WASMVerifiableRekeyCommitments,
};
use crate::factors::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMEncryptionContext, WASMPseudonymizationDomain,
    WASMPseudonymizationInfo,
};
use crate::transcryptor::wasm::types::WASMTranscryptor;
use crate::transcryptor::Transcryptor;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
impl WASMTranscryptor {
    /// Generate the public commitments (combined per transition) for a
    /// pseudonymization info.
    #[wasm_bindgen(js_name = pseudonymizationCommitments)]
    pub fn pseudonymization_commitments(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiablePseudonymizationCommitments {
        let info = self.0.pseudonymization_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        );
        WASMVerifiablePseudonymizationCommitments::from(Transcryptor::pseudonymization_commitment(
            &info,
        ))
    }

    /// Generate the public commitment for an attribute rekey transition.
    #[wasm_bindgen(js_name = attributeRekeyCommitments)]
    pub fn attribute_rekey_commitments(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableRekeyCommitments {
        let info = self.0.attribute_rekey_info(&session_from.0, &session_to.0);
        WASMVerifiableRekeyCommitments::from(Transcryptor::attribute_rekey_commitment(&info))
    }

    /// Generate the public commitment for a pseudonym rekey transition.
    #[wasm_bindgen(js_name = pseudonymRekeyCommitments)]
    pub fn pseudonym_rekey_commitments(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableRekeyCommitments {
        let info = self.0.pseudonym_rekey_info(&session_from.0, &session_to.0);
        WASMVerifiableRekeyCommitments::from(Transcryptor::pseudonym_rekey_commitment(&info))
    }

    /// Perform verifiable pseudonymization.
    ///
    /// Returns a JSON string containing the operation proof — self-contained
    /// in the forward-direction construction.
    #[cfg(all(feature = "serde", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> Result<String, JsValue> {
        use crate::data::verifiable::traits::VerifiablePseudonymizable;

        let mut rng = rand::rng();
        let operation_proof = encrypted
            .0
            .verifiable_pseudonymize(&pseudo_info.0, &mut rng);

        serde_json::to_string(&operation_proof).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(all(feature = "serde", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
    ) -> Result<String, JsValue> {
        use crate::data::verifiable::traits::VerifiablePseudonymizable;

        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let operation_proof = encrypted
            .0
            .verifiable_pseudonymize(&pseudo_info.0, &pk, &mut rng);

        serde_json::to_string(&operation_proof).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Perform verifiable attribute rekey.
    ///
    /// Returns a JSON string containing the operation proof.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifiableAttributeRekey)]
    pub fn verifiable_attribute_rekey(
        &self,
        encrypted: &WASMEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Result<String, JsValue> {
        use crate::data::verifiable::traits::VerifiableRekeyable;

        let mut rng = rand::rng();
        let operation_proof = encrypted.0.verifiable_rekey(&rekey_info.0, &mut rng);

        serde_json::to_string(&operation_proof).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Perform verifiable pseudonym rekey.
    ///
    /// Returns a JSON string containing the operation proof.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = verifiablePseudonymRekey)]
    pub fn verifiable_pseudonym_rekey(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> Result<String, JsValue> {
        use crate::data::verifiable::traits::VerifiableRekeyable;

        let mut rng = rand::rng();
        let info = self.0.pseudonym_rekey_info(&session_from.0, &session_to.0);
        let operation_proof = encrypted.0.verifiable_rekey(&info, &mut rng);

        serde_json::to_string(&operation_proof).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}
