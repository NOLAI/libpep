//! WASM bindings for verifiable transcryptor operations.

use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::commitments::{
    WASMVerifiablePseudonymizationCommitment, WASMVerifiableRekeyCommitment,
    WASMVerifiableTranscryptionCommitment,
};
use crate::factors::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMEncryptionContext, WASMPseudonymizationDomain,
    WASMPseudonymizationInfo,
};
use crate::transcryptor::wasm::types::WASMTranscryptor;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_class = Transcryptor)]
impl WASMTranscryptor {
    /// Generate the public commitments (combined per transition) for a
    /// pseudonymization transition.
    #[wasm_bindgen(js_name = pseudonymizationCommitment)]
    pub fn pseudonymization_commitment(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiablePseudonymizationCommitment {
        WASMVerifiablePseudonymizationCommitment::from(self.0.pseudonymization_commitment(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    /// Generate the public commitment for an attribute rekey transition.
    #[wasm_bindgen(js_name = attributeRekeyCommitment)]
    pub fn attribute_rekey_commitment(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableRekeyCommitment {
        WASMVerifiableRekeyCommitment::from(
            self.0
                .attribute_rekey_commitment(&session_from.0, &session_to.0),
        )
    }

    /// Generate the public commitment for a pseudonym rekey transition.
    #[wasm_bindgen(js_name = pseudonymRekeyCommitment)]
    pub fn pseudonym_rekey_commitment(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableRekeyCommitment {
        WASMVerifiableRekeyCommitment::from(
            self.0
                .pseudonym_rekey_commitment(&session_from.0, &session_to.0),
        )
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

    /// Build the combined public commitments for a transcryption transition
    /// (pseudonymization + attribute rekey). Used by the verifier to check
    /// `verifiableRecordTranscrypt` proofs.
    #[wasm_bindgen(js_name = transcryptionCommitment)]
    pub fn transcryption_commitment(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableTranscryptionCommitment {
        WASMVerifiableTranscryptionCommitment::from(self.0.transcryption_commitment(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    /// Perform verifiable transcryption of a simple record.
    ///
    /// Returns a [`RecordTranscryptionProof`] containing per-item proofs that
    /// the verifier can check against the commitments published for this
    /// transition.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiableRecordTranscrypt)]
    pub fn verifiable_record_transcrypt(
        &self,
        encrypted: &crate::data::wasm::records::WASMEncryptedRecord,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
    ) -> crate::data::wasm::records::WASMRecordTranscryptionProof {
        let enc: crate::data::records::EncryptedRecord = encrypted.clone().into();
        let mut rng = rand::rng();
        let proof = self
            .0
            .verifiable_transcrypt(&enc, &transcryption_info.0, &mut rng);
        crate::data::wasm::records::WASMRecordTranscryptionProof::from(proof)
    }

    /// Non-elgamal3 variant: the recipient session keys the record was
    /// encrypted under must be supplied so the inner rerandomize step's
    /// binding can be proven.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiableRecordTranscrypt)]
    pub fn verifiable_record_transcrypt(
        &self,
        encrypted: &crate::data::wasm::records::WASMEncryptedRecord,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> crate::data::wasm::records::WASMRecordTranscryptionProof {
        let enc: crate::data::records::EncryptedRecord = encrypted.clone().into();
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        let mut rng = rand::rng();
        let proof = self
            .0
            .verifiable_transcrypt(&enc, &transcryption_info.0, &sk, &mut rng);
        crate::data::wasm::records::WASMRecordTranscryptionProof::from(proof)
    }

    /// Perform verifiable transcryption of a long record.
    ///
    /// Returns a [`LongRecordTranscryptionProof`] containing per-item proofs
    /// that the verifier can check against the commitments published for this
    /// transition.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiableLongRecordTranscrypt)]
    pub fn verifiable_long_record_transcrypt(
        &self,
        encrypted: &crate::data::wasm::records::WASMLongEncryptedRecord,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
    ) -> crate::data::wasm::records::WASMLongRecordTranscryptionProof {
        let enc: crate::data::records::LongEncryptedRecord = encrypted.clone().into();
        let mut rng = rand::rng();
        let proof = self
            .0
            .verifiable_transcrypt(&enc, &transcryption_info.0, &mut rng);
        crate::data::wasm::records::WASMLongRecordTranscryptionProof::from(proof)
    }

    /// Non-elgamal3 variant: the recipient session keys the record was
    /// encrypted under must be supplied so the inner rerandomize step's
    /// binding can be proven.
    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = verifiableLongRecordTranscrypt)]
    pub fn verifiable_long_record_transcrypt(
        &self,
        encrypted: &crate::data::wasm::records::WASMLongEncryptedRecord,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> crate::data::wasm::records::WASMLongRecordTranscryptionProof {
        let enc: crate::data::records::LongEncryptedRecord = encrypted.clone().into();
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        let mut rng = rand::rng();
        let proof = self
            .0
            .verifiable_transcrypt(&enc, &transcryption_info.0, &sk, &mut rng);
        crate::data::wasm::records::WASMLongRecordTranscryptionProof::from(proof)
    }
}
