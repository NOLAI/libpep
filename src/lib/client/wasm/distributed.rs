//! WASM bindings for distributed client.

use crate::client::Client;
use crate::client::Distributed;
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
use crate::keys::distribution::{
    AttributeSessionKeyShare, BlindedGlobalKeys, PseudonymSessionKeyShare, SessionKeyShares,
};
use crate::keys::wasm::distribution::WASMBlindedGlobalKeys;
use crate::keys::wasm::types::WASMSessionKeys;
use crate::keys::wasm::{
    WASMAttributeSessionKeyShare, WASMPseudonymSessionKeyShare, WASMSessionKeyShares,
};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A PEP client.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = Client)]
pub struct WASMClient(Client);

#[wasm_bindgen(js_class = Client)]
impl WASMClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        blinded_global_keys: &WASMBlindedGlobalKeys,
        session_key_shares: Vec<WASMSessionKeyShares>,
    ) -> Self {
        let shares: Vec<SessionKeyShares> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShares {
                pseudonym: PseudonymSessionKeyShare(x.0.pseudonym.0),
                attribute: AttributeSessionKeyShare(x.0.attribute.0),
            })
            .collect();
        let blinded_keys = BlindedGlobalKeys {
            pseudonym: blinded_global_keys.0.pseudonym,
            attribute: blinded_global_keys.0.attribute,
        };
        Self(Client::from_shares(blinded_keys, &shares))
    }

    #[wasm_bindgen(js_name = restore)]
    pub fn wasm_restore(keys: &WASMSessionKeys) -> Self {
        Self(Client::restore((*keys).into()))
    }

    #[wasm_bindgen(js_name = dump)]
    pub fn wasm_dump(&self) -> WASMSessionKeys {
        (*self.dump()).into()
    }

    #[wasm_bindgen(js_name = updatePseudonymSessionSecretKey)]
    pub fn wasm_update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: WASMPseudonymSessionKeyShare,
        new_key_share: WASMPseudonymSessionKeyShare,
    ) {
        self.0
            .update_session_secret_key(old_key_share.0, new_key_share.0);
    }

    #[wasm_bindgen(js_name = updateAttributeSessionSecretKey)]
    pub fn wasm_update_attribute_session_secret_key(
        &mut self,
        old_key_share: WASMAttributeSessionKeyShare,
        new_key_share: WASMAttributeSessionKeyShare,
    ) {
        self.0
            .update_session_secret_key(old_key_share.0, new_key_share.0);
    }

    #[wasm_bindgen(js_name = updateSessionSecretKeys)]
    pub fn wasm_update_session_secret_keys(
        &mut self,
        old_key_shares: WASMSessionKeyShares,
        new_key_shares: WASMSessionKeyShares,
    ) {
        self.0
            .update_session_secret_keys(old_key_shares.0, new_key_shares.0);
    }

    #[wasm_bindgen(js_name = decryptPseudonym)]
    #[cfg(feature = "elgamal3")]
    pub fn wasm_decrypt_pseudonym(
        &self,
        encrypted: &WASMEncryptedPseudonym,
    ) -> Option<WASMPseudonym> {
        self.decrypt(&encrypted.0).map(WASMPseudonym::from)
    }

    #[wasm_bindgen(js_name = decryptPseudonym)]
    #[cfg(not(feature = "elgamal3"))]
    pub fn wasm_decrypt_pseudonym(&self, encrypted: &WASMEncryptedPseudonym) -> WASMPseudonym {
        WASMPseudonym::from(self.decrypt(&encrypted.0))
    }

    #[wasm_bindgen(js_name = decryptData)]
    #[cfg(feature = "elgamal3")]
    pub fn wasm_decrypt_data(&self, encrypted: &WASMEncryptedAttribute) -> Option<WASMAttribute> {
        self.decrypt(&encrypted.0).map(WASMAttribute::from)
    }

    #[wasm_bindgen(js_name = decryptData)]
    #[cfg(not(feature = "elgamal3"))]
    pub fn wasm_decrypt_data(&self, encrypted: &WASMEncryptedAttribute) -> WASMAttribute {
        WASMAttribute::from(self.decrypt(&encrypted.0))
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

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = decryptLongPseudonym)]
    pub fn wasm_decrypt_long_pseudonym(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
    ) -> Option<WASMLongPseudonym> {
        self.decrypt(&encrypted.0).map(WASMLongPseudonym::from)
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = decryptLongPseudonym)]
    pub fn wasm_decrypt_long_pseudonym(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
    ) -> WASMLongPseudonym {
        WASMLongPseudonym::from(self.decrypt(&encrypted.0))
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

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = decryptLongData)]
    pub fn wasm_decrypt_long_data(
        &self,
        encrypted: &WASMLongEncryptedAttribute,
    ) -> Option<WASMLongAttribute> {
        self.decrypt(&encrypted.0).map(WASMLongAttribute::from)
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = decryptLongData)]
    pub fn wasm_decrypt_long_data(
        &self,
        encrypted: &WASMLongEncryptedAttribute,
    ) -> WASMLongAttribute {
        WASMLongAttribute::from(self.decrypt(&encrypted.0))
    }

    /// Encrypt a batch of attributes.
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

    /// Encrypt a batch of pseudonyms.
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

    /// Decrypt a batch of encrypted attributes.
    #[cfg(feature = "batch")]
    #[wasm_bindgen(js_name = decryptDataBatch)]
    pub fn wasm_decrypt_data_batch(
        &self,
        encrypted: Vec<WASMEncryptedAttribute>,
    ) -> Result<Vec<WASMAttribute>, wasm_bindgen::JsValue> {
        let rust_encrypted: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
        let decrypted = self
            .0
            .decrypt_batch(&rust_encrypted)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(decrypted.into_iter().map(WASMAttribute::from).collect())
    }

    /// Decrypt a batch of encrypted pseudonyms.
    #[cfg(feature = "batch")]
    #[wasm_bindgen(js_name = decryptPseudonymBatch)]
    pub fn wasm_decrypt_pseudonym_batch(
        &self,
        encrypted: Vec<WASMEncryptedPseudonym>,
    ) -> Result<Vec<WASMPseudonym>, wasm_bindgen::JsValue> {
        let rust_encrypted: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
        let decrypted = self
            .0
            .decrypt_batch(&rust_encrypted)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(decrypted.into_iter().map(WASMPseudonym::from).collect())
    }

    /// Encrypt a batch of long attributes.
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

    /// Encrypt a batch of long pseudonyms.
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

    /// Decrypt a batch of long encrypted attributes.
    #[cfg(all(feature = "batch", feature = "long"))]
    #[wasm_bindgen(js_name = decryptLongDataBatch)]
    pub fn wasm_decrypt_long_data_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedAttribute>,
    ) -> Result<Vec<WASMLongAttribute>, wasm_bindgen::JsValue> {
        let rust_encrypted: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
        let decrypted = self
            .0
            .decrypt_batch(&rust_encrypted)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(decrypted.into_iter().map(WASMLongAttribute::from).collect())
    }

    /// Decrypt a batch of long encrypted pseudonyms.
    #[cfg(all(feature = "batch", feature = "long"))]
    #[wasm_bindgen(js_name = decryptLongPseudonymBatch)]
    pub fn wasm_decrypt_long_pseudonym_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedPseudonym>,
    ) -> Result<Vec<WASMLongPseudonym>, wasm_bindgen::JsValue> {
        let rust_encrypted: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
        let decrypted = self
            .0
            .decrypt_batch(&rust_encrypted)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}", e)))?;
        Ok(decrypted.into_iter().map(WASMLongPseudonym::from).collect())
    }

    /// Encrypt a Record using session keys.
    #[wasm_bindgen(js_name = encryptRecord)]
    pub fn wasm_encrypt_record(&self, record: WASMRecord) -> WASMRecordEncrypted {
        let mut rng = rand::rng();
        use crate::data::records::Record;
        use crate::data::traits::Encryptable;
        let rust_record: Record = record.into();
        let encrypted = rust_record.encrypt(&self.0.keys, &mut rng);
        encrypted.into()
    }

    /// Decrypt an encrypted Record using session keys.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = decryptRecord)]
    pub fn wasm_decrypt_record(&self, encrypted: WASMRecordEncrypted) -> Option<WASMRecord> {
        use crate::data::records::EncryptedRecord;
        use crate::data::traits::Encrypted;
        let rust_encrypted: EncryptedRecord = encrypted.into();
        rust_encrypted.decrypt(&self.0.keys).map(|r| r.into())
    }

    /// Decrypt an encrypted Record using session keys.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = decryptRecord)]
    pub fn wasm_decrypt_record(&self, encrypted: WASMRecordEncrypted) -> WASMRecord {
        use crate::data::records::EncryptedRecord;
        use crate::data::traits::Encrypted;
        let rust_encrypted: EncryptedRecord = encrypted.into();
        rust_encrypted.decrypt(&self.0.keys).into()
    }

    /// Encrypt a LongRecord using session keys.
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongRecord)]
    pub fn wasm_encrypt_long_record(&self, record: WASMLongRecord) -> WASMLongRecordEncrypted {
        let mut rng = rand::rng();
        use crate::data::records::LongRecord;
        use crate::data::traits::Encryptable;
        let rust_record: LongRecord = record.into();
        let encrypted = rust_record.encrypt(&self.0.keys, &mut rng);
        encrypted.into()
    }

    /// Decrypt an encrypted LongRecord using session keys.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = decryptLongRecord)]
    pub fn wasm_decrypt_long_record(
        &self,
        encrypted: WASMLongRecordEncrypted,
    ) -> Option<WASMLongRecord> {
        use crate::data::records::LongEncryptedRecord;
        use crate::data::traits::Encrypted;
        let rust_encrypted: LongEncryptedRecord = encrypted.into();
        rust_encrypted.decrypt(&self.0.keys).map(|r| r.into())
    }

    /// Decrypt an encrypted LongRecord using session keys.
    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = decryptLongRecord)]
    pub fn wasm_decrypt_long_record(&self, encrypted: WASMLongRecordEncrypted) -> WASMLongRecord {
        use crate::data::records::LongEncryptedRecord;
        use crate::data::traits::Encrypted;
        let rust_encrypted: LongEncryptedRecord = encrypted.into();
        rust_encrypted.decrypt(&self.0.keys).into()
    }

    /// Encrypt a PEPJSONValue using session keys.
    #[cfg(feature = "json")]
    #[wasm_bindgen(js_name = encryptJSON)]
    pub fn wasm_encrypt_json(&self, value: WASMPEPJSONValue) -> WASMEncryptedPEPJSONValue {
        let mut rng = rand::rng();
        use crate::data::traits::Encryptable;
        let rust_value = value.0;
        let encrypted = rust_value.encrypt(&self.0.keys, &mut rng);
        WASMEncryptedPEPJSONValue(encrypted)
    }

    /// Decrypt an encrypted PEPJSONValue using session keys.
    #[cfg(all(feature = "json", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = decryptJSON)]
    pub fn wasm_decrypt_json(
        &self,
        encrypted: WASMEncryptedPEPJSONValue,
    ) -> Option<WASMPEPJSONValue> {
        use crate::data::traits::Encrypted;
        encrypted.0.decrypt(&self.0.keys).map(WASMPEPJSONValue)
    }

    /// Decrypt an encrypted PEPJSONValue using session keys.
    #[cfg(all(feature = "json", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = decryptJSON)]
    pub fn wasm_decrypt_json(&self, encrypted: WASMEncryptedPEPJSONValue) -> WASMPEPJSONValue {
        use crate::data::traits::Encrypted;
        WASMPEPJSONValue(encrypted.0.decrypt(&self.0.keys))
    }
}
