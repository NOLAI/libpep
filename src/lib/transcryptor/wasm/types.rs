//! WASM bindings for transcryptor types.

#[cfg(feature = "long")]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::data::simple::{EncryptedAttribute, EncryptedPseudonym};
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

    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> WASMEncryptedPseudonym {
        WASMEncryptedPseudonym::from(
            self.pseudonymize(&encrypted.0, &PseudonymizationInfo::from(pseudo_info)),
        )
    }

    #[cfg(feature = "batch")]
    #[wasm_bindgen(js_name = rekeyBatch)]
    pub fn wasm_rekey_batch(
        &self,
        encrypted: Vec<WASMEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Result<Vec<WASMEncryptedAttribute>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<EncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self
            .rekey_batch(
                &mut encrypted,
                &AttributeRekeyInfo::from(rekey_info),
                &mut rng,
            )
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(result
            .into_vec()
            .into_iter()
            .map(WASMEncryptedAttribute::from)
            .collect())
    }

    #[cfg(feature = "batch")]
    #[wasm_bindgen(js_name = pseudonymizeBatch)]
    pub fn wasm_pseudonymize_batch(
        &self,
        encrypted: Vec<WASMEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> Result<Vec<WASMEncryptedPseudonym>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<EncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self
            .pseudonymize_batch(
                &mut encrypted,
                &PseudonymizationInfo::from(pseudonymization_info),
                &mut rng,
            )
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(result
            .into_vec()
            .into_iter()
            .map(WASMEncryptedPseudonym::from)
            .collect())
    }

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
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = pseudonymizeLong)]
    pub fn wasm_pseudonymize_long(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> WASMLongEncryptedPseudonym {
        WASMLongEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudonymization_info),
        ))
    }

    /// Rekey a batch of long encrypted attributes from one session to another.
    #[cfg(all(feature = "long", feature = "batch"))]
    #[wasm_bindgen(js_name = rekeyLongBatch)]
    pub fn wasm_rekey_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Result<Vec<WASMLongEncryptedAttribute>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<LongEncryptedAttribute> =
            encrypted.into_iter().map(|e| e.0).collect();
        let result = self
            .rekey_batch(
                &mut encrypted,
                &AttributeRekeyInfo::from(rekey_info),
                &mut rng,
            )
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(result
            .into_vec()
            .into_iter()
            .map(WASMLongEncryptedAttribute::from)
            .collect())
    }

    /// Pseudonymize a batch of long encrypted pseudonyms from one domain/session to another.
    #[cfg(all(feature = "long", feature = "batch"))]
    #[wasm_bindgen(js_name = pseudonymizeLongBatch)]
    pub fn wasm_pseudonymize_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> Result<Vec<WASMLongEncryptedPseudonym>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<LongEncryptedPseudonym> =
            encrypted.into_iter().map(|e| e.0).collect();
        let result = self
            .pseudonymize_batch(
                &mut encrypted,
                &PseudonymizationInfo::from(pseudonymization_info),
                &mut rng,
            )
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(result
            .into_vec()
            .into_iter()
            .map(WASMLongEncryptedPseudonym::from)
            .collect())
    }

    /// Transcrypt an EncryptedPEPJSONValue from one context to another.
    #[cfg(feature = "json")]
    #[wasm_bindgen(js_name = transcryptJSON)]
    pub fn transcrypt_json(
        &self,
        encrypted: &crate::data::wasm::json::WASMEncryptedPEPJSONValue,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
    ) -> crate::data::wasm::json::WASMEncryptedPEPJSONValue {
        let transcrypted = self.transcrypt(&encrypted.0, &transcryption_info.0);
        crate::data::wasm::json::WASMEncryptedPEPJSONValue(transcrypted)
    }

    /// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
    #[cfg(all(feature = "json", feature = "batch"))]
    #[wasm_bindgen(js_name = transcryptJSONBatch)]
    pub fn transcrypt_json_batch(
        &self,
        values: Vec<crate::data::wasm::json::WASMEncryptedPEPJSONValue>,
        transcryption_info: &crate::factors::wasm::contexts::WASMTranscryptionInfo,
    ) -> Result<Vec<crate::data::wasm::json::WASMEncryptedPEPJSONValue>, wasm_bindgen::JsValue>
    {
        let mut rng = rand::rng();
        let mut rust_values: Vec<_> = values.into_iter().map(|v| v.0).collect();
        let transcrypted = self
            .transcrypt_batch(&mut rust_values, &transcryption_info.0, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(transcrypted
            .into_vec()
            .into_iter()
            .map(crate::data::wasm::json::WASMEncryptedPEPJSONValue)
            .collect())
    }

    /// Transcrypt an EncryptedRecord from one context to another.
    #[wasm_bindgen(js_name = transcryptRecord)]
    pub fn transcrypt_record(
        &self,
        encrypted: WASMRecordEncrypted,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> WASMRecordEncrypted {
        use crate::data::records::EncryptedRecord;
        use crate::data::traits::Transcryptable;
        let rust_encrypted: EncryptedRecord = encrypted.into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0);
        transcrypted.into()
    }

    /// Transcrypt a LongEncryptedRecord from one context to another.
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = transcryptLongRecord)]
    pub fn transcrypt_long_record(
        &self,
        encrypted: WASMLongRecordEncrypted,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> WASMLongRecordEncrypted {
        use crate::data::records::LongEncryptedRecord;
        use crate::data::traits::Transcryptable;
        let rust_encrypted: LongEncryptedRecord = encrypted.into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0);
        transcrypted.into()
    }

    /// Transcrypt a batch of EncryptedRecords and shuffle their order.
    #[cfg(feature = "batch")]
    #[wasm_bindgen(js_name = transcryptRecordBatch)]
    pub fn transcrypt_record_batch(
        &self,
        records: Vec<WASMRecordEncrypted>,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> Result<Vec<WASMRecordEncrypted>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let mut rust_records: Vec<crate::data::records::EncryptedRecord> =
            records.into_iter().map(|r| r.into()).collect();
        let transcrypted = self
            .transcrypt_batch(&mut rust_records, &transcryption_info.0, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(transcrypted
            .into_vec()
            .into_iter()
            .map(WASMRecordEncrypted::from)
            .collect())
    }

    /// Transcrypt a batch of LongEncryptedRecords and shuffle their order.
    #[cfg(all(feature = "long", feature = "batch"))]
    #[wasm_bindgen(js_name = transcryptLongRecordBatch)]
    pub fn transcrypt_long_record_batch(
        &self,
        records: Vec<WASMLongRecordEncrypted>,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> Result<Vec<WASMLongRecordEncrypted>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let mut rust_records: Vec<crate::data::records::LongEncryptedRecord> =
            records.into_iter().map(|r| r.into()).collect();
        let transcrypted = self
            .transcrypt_batch(&mut rust_records, &transcryption_info.0, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(transcrypted
            .into_vec()
            .into_iter()
            .map(WASMLongRecordEncrypted::from)
            .collect())
    }
}
