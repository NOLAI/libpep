//! WASM bindings for transcryptor types.

#[cfg(feature = "long")]
use crate::data::wasm::long::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
#[cfg(feature = "long")]
use crate::data::wasm::records::WASMLongRecordEncrypted;
use crate::data::wasm::records::WASMRecordEncrypted;
use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMEncryptionContext, WASMPseudonymizationDomain,
    WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
use crate::factors::wasm::types::WASMPseudonymRekeyFactor;
use crate::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymizationInfo, PseudonymizationSecret,
};
use crate::transcryptor::Transcryptor;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A PEP transcryptor system.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = Transcryptor)]
pub struct WASMTranscryptor(pub(crate) Transcryptor);

#[wasm_bindgen(js_class = Transcryptor)]
impl WASMTranscryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonymisation_secret: &str, rekeying_secret: &str) -> Self {
        Self(Transcryptor::new(
            PseudonymizationSecret::from(pseudonymisation_secret.as_bytes().into()),
            EncryptionSecret::from(rekeying_secret.as_bytes().into()),
        ))
    }

    #[wasm_bindgen(js_name = attributeRekeyInfo)]
    pub fn wasm_attribute_rekey_info(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMAttributeRekeyInfo {
        WASMAttributeRekeyInfo::from(self.attribute_rekey_info(&session_from.0, &session_to.0))
    }

    #[wasm_bindgen(js_name = pseudonymRekeyInfo)]
    pub fn wasm_pseudonym_rekey_info(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMPseudonymRekeyFactor {
        WASMPseudonymRekeyFactor::from(self.pseudonym_rekey_info(&session_from.0, &session_to.0))
    }

    #[wasm_bindgen(js_name = pseudonymizationInfo)]
    pub fn wasm_pseudonymization_info(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo::from(self.pseudonymization_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    #[wasm_bindgen(js_name = transcryptionInfo)]
    pub fn wasm_transcryption_info(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMTranscryptionInfo {
        WASMTranscryptionInfo::from(self.transcryption_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    #[wasm_bindgen(js_name = rekey)]
    pub fn wasm_rekey(
        &self,
        encrypted: &WASMEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> WASMEncryptedAttribute {
        WASMEncryptedAttribute::from(
            self.rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)),
        )
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> WASMEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudo_info),
            &mut rng,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
    ) -> WASMEncryptedPseudonym {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        WASMEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudo_info),
            &pk,
            &mut rng,
        ))
    }

    // Batch methods are exposed as free wasm-bindgen functions in
    // `crate::transcryptor::wasm::batch`; they wrap `EncryptedBatch`
    // internally and avoid duplicating the dispatch logic here.

    // Long data type methods

    /// Rekey a long encrypted attribute from one session to another.
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = rekeyLong)]
    pub fn wasm_rekey_long(
        &self,
        encrypted: &WASMLongEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> WASMLongEncryptedAttribute {
        WASMLongEncryptedAttribute::from(
            self.rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)),
        )
    }

    /// Pseudonymize a long encrypted pseudonym from one domain/session to another.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = pseudonymizeLong)]
    pub fn wasm_pseudonymize_long(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> WASMLongEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMLongEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudonymization_info),
            &mut rng,
        ))
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = pseudonymizeLong)]
    pub fn wasm_pseudonymize_long(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudonymization_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
    ) -> WASMLongEncryptedPseudonym {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        WASMLongEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudonymization_info),
            &pk,
            &mut rng,
        ))
    }

    // Long batch methods: see free functions in
    // `crate::transcryptor::wasm::batch`.

    /// Transcrypt an EncryptedPEPJSONValue from one context to another.
    #[cfg(all(feature = "json", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptJSON)]
    pub fn transcrypt_json(
        &self,
        encrypted: &crate::data::wasm::json::WASMEncryptedPEPJSONValue,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
    ) -> crate::data::wasm::json::WASMEncryptedPEPJSONValue {
        let mut rng = rand::rng();
        let transcrypted = self.transcrypt(&encrypted.0, &transcryption_info.0, &mut rng);
        crate::data::wasm::json::WASMEncryptedPEPJSONValue(transcrypted)
    }

    #[cfg(all(feature = "json", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = transcryptJSON)]
    pub fn transcrypt_json(
        &self,
        encrypted: &crate::data::wasm::json::WASMEncryptedPEPJSONValue,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> crate::data::wasm::json::WASMEncryptedPEPJSONValue {
        let mut rng = rand::rng();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        let transcrypted = self.transcrypt(&encrypted.0, &transcryption_info.0, &keys, &mut rng);
        crate::data::wasm::json::WASMEncryptedPEPJSONValue(transcrypted)
    }

    // JSON batch methods: see free functions in
    // `crate::transcryptor::wasm::batch`.

    /// Transcrypt an EncryptedRecord from one context to another.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcryptRecord)]
    pub fn transcrypt_record(
        &self,
        encrypted: WASMRecordEncrypted,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> WASMRecordEncrypted {
        use crate::data::records::EncryptedRecord;
        use crate::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: EncryptedRecord = encrypted.into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &mut rng);
        transcrypted.into()
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptRecord)]
    pub fn transcrypt_record(
        &self,
        encrypted: WASMRecordEncrypted,
        transcryption_info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> WASMRecordEncrypted {
        use crate::data::records::EncryptedRecord;
        use crate::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: EncryptedRecord = encrypted.into();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &keys, &mut rng);
        transcrypted.into()
    }

    /// Transcrypt a LongEncryptedRecord from one context to another.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptLongRecord)]
    pub fn transcrypt_long_record(
        &self,
        encrypted: WASMLongRecordEncrypted,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> WASMLongRecordEncrypted {
        use crate::data::records::LongEncryptedRecord;
        use crate::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: LongEncryptedRecord = encrypted.into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &mut rng);
        transcrypted.into()
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = transcryptLongRecord)]
    pub fn transcrypt_long_record(
        &self,
        encrypted: WASMLongRecordEncrypted,
        transcryption_info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> WASMLongRecordEncrypted {
        use crate::data::records::LongEncryptedRecord;
        use crate::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: LongEncryptedRecord = encrypted.into();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &keys, &mut rng);
        transcrypted.into()
    }

    // Record batch methods: see free functions in
    // `crate::transcryptor::wasm::batch`.
}
