//! WASM bindings for PEP JSON encryption.

use crate::contexts::{WASMEncryptionContext, WASMPseudonymizationDomain};
use crate::factors::secrets::{WASMEncryptionSecret, WASMPseudonymizationSecret};
#[cfg(feature = "batch")]
use crate::factors::types::WASMTranscryptionInfo;
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::WASMGlobalPublicKeys;
#[cfg(all(feature = "insecure", feature = "offline"))]
use crate::keys::types::WASMGlobalSecretKeys;
use crate::keys::types::WASMSessionKeys;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::WASMSessionPublicKeys;
use libpep::client::{decrypt, encrypt};
#[cfg(feature = "batch")]
use libpep::client::{decrypt_batch, encrypt_batch};
#[cfg(all(feature = "offline", feature = "insecure"))]
use libpep::client::{decrypt_global, encrypt_global};
use libpep::data::json::builder::PepJsonBuilder;
use libpep::data::json::data::{EncryptedPepJsonValue, PepJsonValue};
use libpep::data::json::structure::JsonStructure;
use libpep::data::json::utils;
use libpep::data::traits::Transcryptable;
use libpep::factors::TranscryptionInfo;
#[cfg(all(feature = "offline", feature = "insecure"))]
use libpep::keys::GlobalPublicKeys;
use libpep::keys::SessionKeys;
#[cfg(all(feature = "offline", feature = "insecure"))]
use libpep::keys::{
    AttributeGlobalPublicKey, AttributeGlobalSecretKey, PseudonymGlobalPublicKey,
    PseudonymGlobalSecretKey, PublicKey, SecretKey,
};
#[cfg(feature = "batch")]
use libpep::transcryptor::transcrypt_batch;
use serde_json::Value;
use wasm_bindgen::prelude::*;

/// A PEP JSON value that can be encrypted.
///
/// This wraps JSON values where primitive types are stored as unencrypted PEP types.
#[wasm_bindgen(js_name = PepJsonValue)]
#[derive(Clone)]
pub struct WASMPepJsonValue(pub(crate) PepJsonValue);

#[wasm_bindgen(js_class = PepJsonValue)]
impl WASMPepJsonValue {
    /// Create a PepJsonValue from a regular JavaScript value.
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON-serializable JavaScript value
    ///
    /// # Returns
    ///
    /// A PepJsonValue
    #[wasm_bindgen(js_name = fromValue)]
    pub fn from_value(value: JsValue) -> Result<WASMPepJsonValue, JsValue> {
        let json_value: Value = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON value: {}", e)))?;
        Ok(Self(PepJsonValue::from_value(&json_value)))
    }

    /// Convert this PepJsonValue to a regular JavaScript value.
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

    /// Get the structure/shape of this PepJsonValue.
    ///
    /// # Returns
    ///
    /// A JsonStructure describing the shape
    #[wasm_bindgen]
    pub fn structure(&self) -> WASMJsonStructure {
        WASMJsonStructure(self.0.structure())
    }

    /// Pads this PepJsonValue to match a target structure by adding external padding blocks.
    ///
    /// This method adds external padding blocks (separate from PKCS#7 padding) to
    /// LongString and LongPseudonym variants to ensure all instances have the same
    /// number of blocks when encrypted. This is necessary for batch transcryption where
    /// all values must have identical structure.
    ///
    /// # Arguments
    ///
    /// * `structure` - The target structure specifying the number of blocks for each field
    ///
    /// # Returns
    ///
    /// A padded PepJsonValue with padding blocks added where necessary
    ///
    /// # Errors
    ///
    /// Throws an error if the current structure doesn't match the target structure type
    /// or if the current size exceeds the target size
    #[wasm_bindgen(js_name = padTo)]
    pub fn pad_to(&self, structure: &WASMJsonStructure) -> Result<WASMPepJsonValue, JsValue> {
        self.0
            .pad_to(&structure.0)
            .map(Self)
            .map_err(|e| JsValue::from_str(&format!("Padding failed: {}", e)))
    }
}

/// An encrypted PEP JSON value.
///
/// This wraps JSON values where primitive types are encrypted as PEP types.
#[wasm_bindgen(js_name = EncryptedPepJsonValue)]
#[derive(Clone)]
pub struct WASMEncryptedPepJsonValue(pub(crate) EncryptedPepJsonValue);

#[wasm_bindgen(js_class = EncryptedPepJsonValue)]
impl WASMEncryptedPepJsonValue {
    /// Get the structure/shape of this EncryptedPepJsonValue.
    ///
    /// # Returns
    ///
    /// A JsonStructure describing the shape
    #[wasm_bindgen]
    pub fn structure(&self) -> WASMJsonStructure {
        WASMJsonStructure(self.0.structure())
    }

    #[cfg(feature = "elgamal3")]
    /// Transcrypt this EncryptedPepJsonValue from one context to another.
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
    /// A transcrypted EncryptedPepJsonValue
    #[wasm_bindgen]
    pub fn transcrypt(
        &self,
        from_domain: &WASMPseudonymizationDomain,
        to_domain: &WASMPseudonymizationDomain,
        from_session: &WASMEncryptionContext,
        to_session: &WASMEncryptionContext,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Result<WASMEncryptedPepJsonValue, JsValue> {
        let mut rng = rand::rng();
        let transcryption_info = TranscryptionInfo::new(
            &from_domain.0,
            &to_domain.0,
            &from_session.0,
            &to_session.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );

        let transcrypted = self.0.transcrypt(&transcryption_info, &mut rng);
        Ok(WASMEncryptedPepJsonValue(transcrypted))
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Transcrypt this EncryptedPepJsonValue from one context to another.
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
    /// A transcrypted EncryptedPepJsonValue
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub fn transcrypt(
        &self,
        from_domain: &WASMPseudonymizationDomain,
        to_domain: &WASMPseudonymizationDomain,
        from_session: &WASMEncryptionContext,
        to_session: &WASMEncryptionContext,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
        public_key: &WASMSessionPublicKeys,
    ) -> Result<WASMEncryptedPepJsonValue, JsValue> {
        let mut rng = rand::rng();
        let pk = libpep::keys::SessionPublicKeys::from(public_key);
        let transcryption_info = TranscryptionInfo::new(
            &from_domain.0,
            &to_domain.0,
            &from_session.0,
            &to_session.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );

        let transcrypted = self.0.transcrypt(&transcryption_info, &pk, &mut rng);
        Ok(WASMEncryptedPepJsonValue(transcrypted))
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
    /// An EncryptedPepJsonValue
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json_str: &str) -> Result<WASMEncryptedPepJsonValue, JsValue> {
        let value: EncryptedPepJsonValue = serde_json::from_str(json_str)
            .map_err(|e| JsValue::from_str(&format!("Deserialization failed: {}", e)))?;
        Ok(WASMEncryptedPepJsonValue(value))
    }
}

/// A JSON structure descriptor that describes the shape of an EncryptedPepJsonValue.
#[wasm_bindgen(js_name = JsonStructure)]
#[derive(Clone)]
pub struct WASMJsonStructure(pub(crate) JsonStructure);

#[wasm_bindgen(js_class = JsonStructure)]
impl WASMJsonStructure {
    /// Convert to a human-readable string.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_json_string(&self) -> String {
        format!("{:?}", self.0)
    }

    /// Compare two structures for equality.
    #[wasm_bindgen(js_name = equals)]
    pub fn equals(&self, other: &WASMJsonStructure) -> bool {
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

/// Builder for constructing PepJsonValue objects with mixed attribute and pseudonym fields.
#[derive(Default)]
#[wasm_bindgen(js_name = PepJsonBuilder)]
pub struct WASMPepJsonBuilder {
    builder: PepJsonBuilder,
}

#[wasm_bindgen(js_class = PepJsonBuilder)]
impl WASMPepJsonBuilder {
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
    /// A PepJsonBuilder
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(
        value: JsValue,
        pseudonyms: Vec<String>,
    ) -> Result<WASMPepJsonBuilder, JsValue> {
        let json_value: Value = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON value: {}", e)))?;

        let pseudonym_refs: Vec<&str> = pseudonyms.iter().map(|s| s.as_str()).collect();
        let builder = PepJsonBuilder::from_json(&json_value, &pseudonym_refs)
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
    pub fn attribute(mut self, key: &str, value: JsValue) -> Result<WASMPepJsonBuilder, JsValue> {
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
    pub fn pseudonym(mut self, key: &str, value: &str) -> WASMPepJsonBuilder {
        self.builder = self.builder.pseudonym(key, value);
        self
    }

    /// Build the final PepJsonValue object.
    ///
    /// # Returns
    ///
    /// A PepJsonValue
    #[wasm_bindgen]
    pub fn build(self) -> WASMPepJsonValue {
        WASMPepJsonValue(self.builder.build())
    }
}

/// Encrypt a PepJsonValue using session keys.
///
/// # Arguments
///
/// * `value` - PepJsonValue to encrypt
/// * `session_keys` - Session keys containing public and secret keys for both pseudonyms and attributes
///
/// # Returns
///
/// An EncryptedPepJsonValue
#[wasm_bindgen(js_name = encryptJson)]
pub fn wasm_encrypt_json(
    value: &WASMPepJsonValue,
    session_keys: &WASMSessionKeys,
) -> WASMEncryptedPepJsonValue {
    let mut rng = rand::rng();
    let keys: SessionKeys = (*session_keys).into();
    let encrypted = encrypt(&value.0, &keys.public(), &mut rng);
    WASMEncryptedPepJsonValue(encrypted)
}

/// Batch encrypt a list of PepJsonValues using session keys.
/// All values must have the same structure, and the resulting encrypted values will be padded to match the maximum block counts for that structure.
///
/// # Arguments
/// * `values` - Array of PepJsonValue objects to encrypt
/// * `session_keys` - Session keys containing public and secret keys for both pseudonyms and
///
/// # Returns
/// An array of EncryptedPepJsonValue objects, all with the same structure and padded to match the maximum block counts for that structure
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = encryptJsonBatch)]
pub fn wasm_encrypt_json_batch(
    values: Vec<WASMPepJsonValue>,
    session_keys: &WASMSessionKeys,
) -> Result<Vec<WASMEncryptedPepJsonValue>, JsValue> {
    let mut rng = rand::rng();
    let keys: SessionKeys = (*session_keys).into();
    let rust_values: Vec<PepJsonValue> = values.into_iter().map(|v| v.0).collect();
    let encrypted = encrypt_batch(&rust_values, &keys.public(), &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    Ok(encrypted
        .into_items()
        .into_iter()
        .map(WASMEncryptedPepJsonValue)
        .collect())
}
/// Decrypt an EncryptedPepJsonValue using session keys.
///
/// # Arguments
///
/// * `encrypted` - EncryptedPepJsonValue to decrypt
/// * `session_keys` - Session keys containing public and secret keys for both pseudonyms and attributes
///
/// # Returns
///
/// A PepJsonValue
#[wasm_bindgen(js_name = decryptJson)]
pub fn wasm_decrypt_json(
    encrypted: &WASMEncryptedPepJsonValue,
    session_keys: &WASMSessionKeys,
) -> Result<WASMPepJsonValue, JsValue> {
    let keys: SessionKeys = (*session_keys).into();
    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt(&encrypted.0, &keys)
        .ok_or_else(|| JsValue::from_str("Decryption failed: key mismatch"))?;
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt(&encrypted.0, &keys);
    Ok(WASMPepJsonValue(decrypted))
}

/// Decrypt a batch of EncryptedPepJsonValues using session keys.
///
/// # Arguments
///
/// * `encrypted` - Array of EncryptedPepJsonValue objects to decrypt
/// * `session_keys` - Session keys containing public and secret keys for both pseudonyms and
///
/// # Returns
/// An array of PepJsonValue objects
/// # Errors
/// Returns an error if any value fails to decrypt
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = decryptJsonBatch)]
pub fn wasm_decrypt_json_batch(
    encrypted: Vec<WASMEncryptedPepJsonValue>,
    session_keys: &WASMSessionKeys,
) -> Result<Vec<WASMPepJsonValue>, JsValue> {
    let keys: SessionKeys = (*session_keys).into();
    let rust_encrypted: Vec<EncryptedPepJsonValue> = encrypted.into_iter().map(|v| v.0).collect();
    let decrypted =
        decrypt_batch(&rust_encrypted, &keys).map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    Ok(decrypted.into_iter().map(WASMPepJsonValue).collect())
}

#[cfg(feature = "elgamal3")]
/// Transcrypt a batch of EncryptedPepJsonValues using a TranscryptionInfo object.
///
/// # Arguments
///
/// * `values` - Array of EncryptedPepJsonValue objects
/// * `transcryption_info` - TranscryptionInfo containing all transcryption parameters
///
/// # Returns
///
/// A shuffled array of transcrypted EncryptedPepJsonValue objects
///
/// # Errors
///
/// Returns an error if the values don't all have the same structure
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = transcryptJsonBatch)]
pub fn wasm_transcrypt_json_batch(
    values: Vec<WASMEncryptedPepJsonValue>,
    transcryption_info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedPepJsonValue>, JsValue> {
    let mut rng = rand::rng();
    let mut rust_values: Vec<EncryptedPepJsonValue> = values.into_iter().map(|v| v.0).collect();
    let transcrypted = transcrypt_batch(&mut rust_values, &transcryption_info.0, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    Ok(transcrypted
        .into_iter()
        .map(WASMEncryptedPepJsonValue)
        .collect())
}

#[cfg(not(feature = "elgamal3"))]
/// Transcrypt a batch of EncryptedPepJsonValues using a TranscryptionInfo object.
///
/// # Arguments
///
/// * `values` - Array of EncryptedPepJsonValue objects
/// * `transcryption_info` - TranscryptionInfo containing all transcryption parameters
///
/// # Returns
///
/// A shuffled array of transcrypted EncryptedPepJsonValue objects
///
/// # Errors
///
/// Returns an error if the values don't all have the same structure
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = transcryptJsonBatch)]
pub fn wasm_transcrypt_json_batch(
    values: Vec<WASMEncryptedPepJsonValue>,
    transcryption_info: &WASMTranscryptionInfo,
    public_key: &WASMSessionPublicKeys,
) -> Result<Vec<WASMEncryptedPepJsonValue>, JsValue> {
    let pk = libpep::keys::SessionPublicKeys::from(public_key);
    let mut rng = rand::rng();
    let mut rust_values: Vec<EncryptedPepJsonValue> = values.into_iter().map(|v| v.0).collect();
    let transcrypted = transcrypt_batch(&mut rust_values, &transcryption_info.0, &pk, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    Ok(transcrypted
        .into_iter()
        .map(WASMEncryptedPepJsonValue)
        .collect())
}

/// Encrypt a PepJsonValue using global public keys.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
#[cfg(all(feature = "offline", feature = "insecure"))]
#[wasm_bindgen(js_name = encryptJsonGlobal)]
pub fn wasm_encrypt_json_global(
    value: &WASMPepJsonValue,
    global_keys: &WASMGlobalPublicKeys,
) -> WASMEncryptedPepJsonValue {
    let mut rng = rand::rng();
    let keys = GlobalPublicKeys {
        pseudonym: PseudonymGlobalPublicKey::from_point(*global_keys.pseudonym().0),
        attribute: AttributeGlobalPublicKey::from_point(*global_keys.attribute().0),
    };
    WASMEncryptedPepJsonValue(encrypt_global(&value.0, &keys, &mut rng))
}

/// Decrypt an EncryptedPepJsonValue using global secret keys.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "offline"))]
#[wasm_bindgen(js_name = decryptJsonGlobal)]
pub fn wasm_decrypt_json_global(
    encrypted: &WASMEncryptedPepJsonValue,
    global_secret_keys: &WASMGlobalSecretKeys,
) -> Result<WASMPepJsonValue, JsValue> {
    let keys = libpep::keys::GlobalSecretKeys {
        pseudonym: PseudonymGlobalSecretKey::from_scalar(global_secret_keys.pseudonym().0 .0),
        attribute: AttributeGlobalSecretKey::from_scalar(global_secret_keys.attribute().0 .0),
    };
    #[cfg(feature = "elgamal3")]
    let decrypted = decrypt_global(&encrypted.0, &keys)
        .ok_or_else(|| JsValue::from_str("Decryption failed: key mismatch"))?;
    #[cfg(not(feature = "elgamal3"))]
    let decrypted = decrypt_global(&encrypted.0, &keys);
    Ok(WASMPepJsonValue(decrypted))
}

// JSON utility functions

/// Convert a boolean to a single byte (0x00 for false, 0x01 for true).
#[wasm_bindgen(js_name = boolToByte)]
pub fn wasm_bool_to_byte(b: bool) -> u8 {
    utils::bool_to_byte(b)
}

/// Convert a byte to a boolean. Returns an error if the byte is neither 0x00 nor 0x01.
#[wasm_bindgen(js_name = byteToBool)]
pub fn wasm_byte_to_bool(byte: u8) -> Result<bool, JsValue> {
    utils::byte_to_bool(byte).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Convert a JSON number to bytes (9 bytes: 1 byte type tag + 8 bytes data).
#[wasm_bindgen(js_name = numberToBytes)]
pub fn wasm_number_to_bytes(n: f64) -> Vec<u8> {
    let num = serde_json::Number::from_f64(n).unwrap_or(serde_json::Number::from(0));
    utils::number_to_bytes(&num).to_vec()
}

/// Convert bytes to a JSON number (9 bytes: 1 byte type tag + 8 bytes data).
#[wasm_bindgen(js_name = bytesToNumber)]
pub fn wasm_bytes_to_number(bytes: Vec<u8>) -> Result<f64, JsValue> {
    if bytes.len() != 9 {
        return Err(JsValue::from_str("Expected exactly 9 bytes"));
    }
    let arr: [u8; 9] = bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid byte array"))?;
    let num = utils::bytes_to_number(&arr)
        .map_err(|e| JsValue::from_str(&format!("Invalid number encoding: {e}")))?;
    Ok(num.as_f64().unwrap_or(0.0))
}

/// Unifies multiple JSON structures by taking the maximum block count for each field.
///
/// This function is useful for batch operations where you need to normalize multiple
/// values to have the same structure. It recursively unifies nested structures,
/// taking the maximum block count for strings and pseudonyms.
///
/// # Arguments
///
/// * `structures` - An array of JsonStructure objects to unify
///
/// # Returns
///
/// A unified JsonStructure where string and pseudonym fields have maximum block counts
///
/// # Errors
///
/// Returns an error if the structures are incompatible (different types, array lengths, or object fields)
#[wasm_bindgen(js_name = unifyStructures)]
pub fn wasm_unify_structures(
    structures: Vec<WASMJsonStructure>,
) -> Result<WASMJsonStructure, JsValue> {
    let rust_structures: Vec<JsonStructure> = structures.into_iter().map(|s| s.0).collect();
    libpep::data::json::structure::unify_structures(&rust_structures)
        .map(WASMJsonStructure)
        .map_err(|e| JsValue::from_str(&format!("Unification failed: {}", e)))
}
