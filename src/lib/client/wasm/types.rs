//! WASM bindings for client types.

#[cfg(feature = "offline")]
use crate::client::OfflineClient;
#[cfg(feature = "json")]
use crate::data::wasm::json::{WASMEncryptedPEPJSONValue, WASMPEPJSONValue};
#[cfg(feature = "long")]
use crate::data::wasm::long::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};
#[cfg(feature = "long")]
use crate::data::wasm::records::{WASMLongRecord, WASMLongRecordEncrypted};
use crate::data::wasm::records::{WASMRecord, WASMRecordEncrypted};
use crate::data::wasm::simple::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::keys::wasm::types::WASMGlobalPublicKeys;
use crate::keys::*;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// An offline PEP client.
#[cfg(feature = "offline")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = OfflinePEPClient)]
pub struct WASMOfflinePEPClient(pub(crate) OfflineClient);

#[cfg(feature = "offline")]
#[wasm_bindgen(js_class = OfflinePEPClient)]
impl WASMOfflinePEPClient {
    #[wasm_bindgen(constructor)]
    pub fn new(global_keys: &WASMGlobalPublicKeys) -> Self {
        let global_keys = GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey(*global_keys.pseudonym().0),
            attribute: AttributeGlobalPublicKey(*global_keys.attribute().0),
        };
        Self(OfflineClient::new(global_keys))
    }

    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMAttribute) -> WASMEncryptedAttribute {
        let mut rng = rand::rng();
        WASMEncryptedAttribute::from(self.encrypt(&message.0, &mut rng))
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMEncryptedPseudonym(self.encrypt(&message.0, &mut rng))
    }

    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongPseudonym)]
    pub fn wasm_encrypt_long_pseudonym(
        &self,
        message: &WASMLongPseudonym,
    ) -> WASMLongEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMLongEncryptedPseudonym::from(self.encrypt(&message.0, &mut rng))
    }

    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongData)]
    pub fn wasm_encrypt_long_data(
        &self,
        message: &WASMLongAttribute,
    ) -> WASMLongEncryptedAttribute {
        let mut rng = rand::rng();
        WASMLongEncryptedAttribute::from(self.encrypt(&message.0, &mut rng))
    }

    /// Encrypt a batch of attributes with global keys.
    #[cfg(feature = "batch")]
    #[wasm_bindgen(js_name = encryptDataBatch)]
    pub fn wasm_encrypt_data_batch(
        &self,
        messages: Vec<WASMAttribute>,
    ) -> Result<Vec<WASMEncryptedAttribute>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let rust_messages: Vec<_> = messages.into_iter().map(|m| m.0).collect();
        let encrypted = self
            .0
            .encrypt_batch(&rust_messages, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(encrypted
            .into_iter()
            .map(WASMEncryptedAttribute::from)
            .collect())
    }

    /// Encrypt a batch of pseudonyms with global keys.
    #[cfg(feature = "batch")]
    #[wasm_bindgen(js_name = encryptPseudonymBatch)]
    pub fn wasm_encrypt_pseudonym_batch(
        &self,
        messages: Vec<WASMPseudonym>,
    ) -> Result<Vec<WASMEncryptedPseudonym>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let rust_messages: Vec<_> = messages.into_iter().map(|m| m.0).collect();
        let encrypted = self
            .0
            .encrypt_batch(&rust_messages, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(encrypted.into_iter().map(WASMEncryptedPseudonym).collect())
    }

    /// Encrypt a batch of long attributes with global keys.
    #[cfg(all(feature = "batch", feature = "long"))]
    #[wasm_bindgen(js_name = encryptLongDataBatch)]
    pub fn wasm_encrypt_long_data_batch(
        &self,
        messages: Vec<WASMLongAttribute>,
    ) -> Result<Vec<WASMLongEncryptedAttribute>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let rust_messages: Vec<_> = messages.into_iter().map(|m| m.0).collect();
        let encrypted = self
            .0
            .encrypt_batch(&rust_messages, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(encrypted
            .into_iter()
            .map(WASMLongEncryptedAttribute::from)
            .collect())
    }

    /// Encrypt a batch of long pseudonyms with global keys.
    #[cfg(all(feature = "batch", feature = "long"))]
    #[wasm_bindgen(js_name = encryptLongPseudonymBatch)]
    pub fn wasm_encrypt_long_pseudonym_batch(
        &self,
        messages: Vec<WASMLongPseudonym>,
    ) -> Result<Vec<WASMLongEncryptedPseudonym>, wasm_bindgen::JsValue> {
        let mut rng = rand::rng();
        let rust_messages: Vec<_> = messages.into_iter().map(|m| m.0).collect();
        let encrypted = self
            .0
            .encrypt_batch(&rust_messages, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(encrypted
            .into_iter()
            .map(WASMLongEncryptedPseudonym::from)
            .collect())
    }

    /// Encrypt a Record using global public keys (offline mode).
    #[wasm_bindgen(js_name = encryptRecord)]
    pub fn wasm_encrypt_record(&self, record: WASMRecord) -> WASMRecordEncrypted {
        use crate::data::records::Record;
        use crate::data::traits::Encryptable;
        let mut rng = rand::rng();
        let rust_record: Record = record.into();
        let encrypted = rust_record.encrypt_global(&self.0.global_public_keys, &mut rng);
        encrypted.into()
    }

    /// Encrypt a LongRecord using global public keys (offline mode).
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongRecord)]
    pub fn wasm_encrypt_long_record(&self, record: WASMLongRecord) -> WASMLongRecordEncrypted {
        use crate::data::records::LongRecord;
        use crate::data::traits::Encryptable;
        let mut rng = rand::rng();
        let rust_record: LongRecord = record.into();
        let encrypted = rust_record.encrypt_global(&self.0.global_public_keys, &mut rng);
        encrypted.into()
    }

    /// Encrypt a PEPJSONValue using global public keys (offline mode).
    #[cfg(feature = "json")]
    #[wasm_bindgen(js_name = encryptJSON)]
    pub fn wasm_encrypt_json(&self, value: WASMPEPJSONValue) -> WASMEncryptedPEPJSONValue {
        use crate::data::traits::Encryptable;
        let mut rng = rand::rng();
        let encrypted = value.0.encrypt_global(&self.0.global_public_keys, &mut rng);
        WASMEncryptedPEPJSONValue(encrypted)
    }
}
