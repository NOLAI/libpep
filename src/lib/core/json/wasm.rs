//! WASM bindings for PEP JSON encryption.

use crate::core::json::builder::PEPJSONBuilder;
use crate::core::json::data::{EncryptedPEPJSONValue, PEPJSONValue};
#[cfg(all(feature = "insecure", feature = "offline"))]
use crate::core::json::offline::decrypt_json_global;
#[cfg(feature = "offline")]
use crate::core::json::offline::encrypt_json_global;
use crate::core::json::structure::JSONStructure;
use crate::core::json::transcryption::transcrypt_json_batch;
use crate::core::keys::{GlobalPublicKeys, SessionKeys};
use crate::core::transcryption::contexts::TranscryptionInfo;
use crate::core::transcryption::wasm::contexts::{
    WASMEncryptionContext, WASMPseudonymizationDomain, WASMTranscryptionInfo,
};
use crate::core::transcryption::wasm::secrets::{WASMEncryptionSecret, WASMPseudonymizationSecret};
#[cfg(feature = "offline")]
use crate::core::wasm::keys::WASMGlobalPublicKeys;
#[cfg(all(feature = "insecure", feature = "offline"))]
use crate::core::wasm::keys::WASMGlobalSecretKeys;
use crate::core::wasm::keys::WASMSessionKeys;
use serde_json::Value;
use wasm_bindgen::prelude::*;

/// A PEP JSON value that can be encrypted.
///
/// This wraps JSON values where primitive types are stored as unencrypted PEP types.
#[wasm_bindgen(js_name = PEPJSONValue)]
#[derive(Clone)]
pub struct WASMPEPJSONValue(pub(crate) PEPJSONValue);

#[wasm_bindgen(js_class = PEPJSONValue)]
impl WASMPEPJSONValue {
    /// Create a PEPJSONValue from a regular JavaScript value.
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON-serializable JavaScript value
    ///
    /// # Returns
    ///
    /// A PEPJSONValue
    #[wasm_bindgen(js_name = fromValue)]
    pub fn from_value(value: JsValue) -> Result<WASMPEPJSONValue, JsValue> {
        let json_value: Value = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON value: {}", e)))?;
        Ok(Self(PEPJSONValue::from_value(&json_value)))
    }

    /// Convert this PEPJSONValue to a regular JavaScript value.
    ///
    /// # Returns
    ///
    /// A JavaScript value (object, array, string, number, boolean, or null)
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let json_value = self
            .0
            .to_value()
            .map_err(|e| JsValue::from_str(&format!("Conversion failed: {}", e)))?;

        serde_wasm_bindgen::to_value(&json_value)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert to JS: {}", e)))
    }
}

/// An encrypted PEP JSON value.
///
/// This wraps JSON values where primitive types are encrypted as PEP types.
#[wasm_bindgen(js_name = EncryptedPEPJSONValue)]
#[derive(Clone)]
pub struct WASMEncryptedPEPJSONValue(pub(crate) EncryptedPEPJSONValue);

#[wasm_bindgen(js_class = EncryptedPEPJSONValue)]
impl WASMEncryptedPEPJSONValue {
    /// Get the structure/shape of this EncryptedPEPJSONValue.
    ///
    /// # Returns
    ///
    /// A JSONStructure describing the shape
    #[wasm_bindgen]
    pub fn structure(&self) -> WASMJSONStructure {
        WASMJSONStructure(self.0.structure())
    }

    /// Transcrypt this EncryptedPEPJSONValue from one context to another.
    ///
    /// # Arguments
    ///
    /// * `from_domain` - Source pseudonymization domain
    /// * `to_domain` - Target pseudonymization domain
    /// * `from_session` - Source encryption session (optional)
    /// * `to_session` - Target encryption session (optional)
    /// * `pseudonymization_secret` - Pseudonymization secret
    /// * `encryption_secret` - Encryption secret
    ///
    /// # Returns
    ///
    /// A transcrypted EncryptedPEPJSONValue
    #[wasm_bindgen]
    pub fn transcrypt(
        &self,
        from_domain: &WASMPseudonymizationDomain,
        to_domain: &WASMPseudonymizationDomain,
        from_session: &WASMEncryptionContext,
        to_session: &WASMEncryptionContext,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Result<WASMEncryptedPEPJSONValue, JsValue> {
        let transcryption_info = TranscryptionInfo::new(
            &from_domain.0,
            &to_domain.0,
            &from_session.0,
            &to_session.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );

        let transcrypted = self.0.transcrypt(&transcryption_info);
        Ok(WASMEncryptedPEPJSONValue(transcrypted))
    }

    /// Serialize to JSON string.
    ///
    /// # Returns
    ///
    /// A JSON string representation
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0)
            .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON string.
    ///
    /// # Arguments
    ///
    /// * `json_str` - A JSON string
    ///
    /// # Returns
    ///
    /// An EncryptedPEPJSONValue
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json_str: &str) -> Result<WASMEncryptedPEPJSONValue, JsValue> {
        let value: EncryptedPEPJSONValue = serde_json::from_str(json_str)
            .map_err(|e| JsValue::from_str(&format!("Deserialization failed: {}", e)))?;
        Ok(WASMEncryptedPEPJSONValue(value))
    }
}

/// A JSON structure descriptor that describes the shape of an EncryptedPEPJSONValue.
#[wasm_bindgen(js_name = JSONStructure)]
#[derive(Clone)]
pub struct WASMJSONStructure(pub(crate) JSONStructure);

#[wasm_bindgen(js_class = JSONStructure)]
impl WASMJSONStructure {
    /// Convert to a human-readable string.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_json_string(&self) -> String {
        format!("{:?}", self.0)
    }

    /// Compare two structures for equality.
    #[wasm_bindgen(js_name = equals)]
    pub fn equals(&self, other: &WASMJSONStructure) -> bool {
        self.0 == other.0
    }

    /// Serialize to JSON string.
    ///
    /// # Returns
    ///
    /// A JSON string representation
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0)
            .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
    }
}

/// Builder for constructing PEPJSONValue objects with mixed attribute and pseudonym fields.
#[derive(Default)]
#[wasm_bindgen(js_name = PEPJSONBuilder)]
pub struct WASMPEPJSONBuilder {
    builder: PEPJSONBuilder,
}

#[wasm_bindgen(js_class = PEPJSONBuilder)]
impl WASMPEPJSONBuilder {
    /// Create a new builder.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder from a JavaScript object, marking specified fields as pseudonyms.
    ///
    /// # Arguments
    ///
    /// * `value` - A JavaScript object (will be converted to JSON)
    /// * `pseudonyms` - An array of field names that should be treated as pseudonyms
    ///
    /// # Returns
    ///
    /// A PEPJSONBuilder
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(
        value: JsValue,
        pseudonyms: Vec<String>,
    ) -> Result<WASMPEPJSONBuilder, JsValue> {
        let json_value: Value = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON value: {}", e)))?;

        let pseudonym_refs: Vec<&str> = pseudonyms.iter().map(|s| s.as_str()).collect();
        let builder = PEPJSONBuilder::from_json(&json_value, &pseudonym_refs)
            .ok_or_else(|| JsValue::from_str("Invalid object or pseudonym field not a string"))?;

        Ok(Self { builder })
    }

    /// Add a field as a regular attribute.
    ///
    /// # Arguments
    ///
    /// * `key` - Field name
    /// * `value` - Field value (any JSON-serializable JavaScript value)
    ///
    /// # Returns
    ///
    /// Self (for chaining)
    #[wasm_bindgen]
    pub fn attribute(mut self, key: &str, value: JsValue) -> Result<WASMPEPJSONBuilder, JsValue> {
        let json_value: Value = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON value: {}", e)))?;
        self.builder = self.builder.attribute(key, json_value);
        Ok(self)
    }

    /// Add a string field as a pseudonym.
    ///
    /// # Arguments
    ///
    /// * `key` - Field name
    /// * `value` - String value
    ///
    /// # Returns
    ///
    /// Self (for chaining)
    #[wasm_bindgen]
    pub fn pseudonym(mut self, key: &str, value: &str) -> WASMPEPJSONBuilder {
        self.builder = self.builder.pseudonym(key, value);
        self
    }

    /// Build the final PEPJSONValue object.
    ///
    /// # Returns
    ///
    /// A PEPJSONValue
    #[wasm_bindgen]
    pub fn build(self) -> WASMPEPJSONValue {
        WASMPEPJSONValue(self.builder.build())
    }
}

/// Encrypt a PEPJSONValue using session keys.
///
/// # Arguments
///
/// * `value` - PEPJSONValue to encrypt
/// * `session_keys` - Session keys containing public and secret keys for both pseudonyms and attributes
///
/// # Returns
///
/// An EncryptedPEPJSONValue
#[wasm_bindgen(js_name = encryptJson)]
pub fn wasm_encrypt_json(
    value: &WASMPEPJSONValue,
    session_keys: &WASMSessionKeys,
) -> WASMEncryptedPEPJSONValue {
    let mut rng = rand::rng();
    let keys: SessionKeys = (*session_keys).into();
    let encrypted = crate::core::json::data::encrypt_json(&value.0, &keys, &mut rng);
    WASMEncryptedPEPJSONValue(encrypted)
}

/// Decrypt an EncryptedPEPJSONValue using session keys.
///
/// # Arguments
///
/// * `encrypted` - EncryptedPEPJSONValue to decrypt
/// * `session_keys` - Session keys containing public and secret keys for both pseudonyms and attributes
///
/// # Returns
///
/// A PEPJSONValue
#[wasm_bindgen(js_name = decryptJson)]
pub fn wasm_decrypt_json(
    encrypted: &WASMEncryptedPEPJSONValue,
    session_keys: &WASMSessionKeys,
) -> Result<WASMPEPJSONValue, JsValue> {
    let keys: SessionKeys = (*session_keys).into();
    let decrypted = crate::core::json::data::decrypt_json(&encrypted.0, &keys)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;
    Ok(WASMPEPJSONValue(decrypted))
}

/// Transcrypt a batch of EncryptedPEPJSONValues using a TranscryptionInfo object.
///
/// # Arguments
///
/// * `values` - Array of EncryptedPEPJSONValue objects
/// * `transcryption_info` - TranscryptionInfo containing all transcryption parameters
///
/// # Returns
///
/// A shuffled array of transcrypted EncryptedPEPJSONValue objects
///
/// # Errors
///
/// Returns an error if the values don't all have the same structure
#[wasm_bindgen(js_name = transcryptJsonBatch)]
pub fn wasm_transcrypt_json_batch(
    values: Vec<WASMEncryptedPEPJSONValue>,
    transcryption_info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedPEPJSONValue>, JsValue> {
    let mut rng = rand::rng();
    let rust_values: Vec<EncryptedPEPJSONValue> = values.into_iter().map(|v| v.0).collect();
    let transcrypted = transcrypt_json_batch(rust_values, &transcryption_info.0, &mut rng)
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(transcrypted
        .into_iter()
        .map(WASMEncryptedPEPJSONValue)
        .collect())
}

/// Encrypt a PEPJSONValue using global public keys.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
#[cfg(feature = "offline")]
#[wasm_bindgen(js_name = encryptJsonGlobal)]
pub fn wasm_encrypt_json_global(
    value: &WASMPEPJSONValue,
    global_keys: &WASMGlobalPublicKeys,
) -> WASMEncryptedPEPJSONValue {
    let mut rng = rand::rng();
    let keys = GlobalPublicKeys {
        pseudonym: (*global_keys.pseudonym().0).into(),
        attribute: (*global_keys.attribute().0).into(),
    };
    WASMEncryptedPEPJSONValue(encrypt_json_global(&value.0, &keys, &mut rng))
}

/// Decrypt an EncryptedPEPJSONValue using global secret keys.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "offline"))]
#[wasm_bindgen(js_name = decryptJsonGlobal)]
pub fn wasm_decrypt_json_global(
    encrypted: &WASMEncryptedPEPJSONValue,
    global_secret_keys: &WASMGlobalSecretKeys,
) -> Result<WASMPEPJSONValue, JsValue> {
    let keys = crate::core::keys::GlobalSecretKeys {
        pseudonym: global_secret_keys.pseudonym().0 .0.into(),
        attribute: global_secret_keys.attribute().0 .0.into(),
    };
    let decrypted = decrypt_json_global(&encrypted.0, &keys)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;
    Ok(WASMPEPJSONValue(decrypted))
}
