//! WASM bindings for PEP JSON encryption.

use crate::arithmetic::ScalarNonZero;
use crate::core::json::builder::PEPJSONBuilder;
use crate::core::json::core::{EncryptedPEPJSONValue, PEPJSONValue};
use crate::core::json::structure::JSONStructure;
use crate::core::json::transcryption::transcrypt_batch;
use crate::core::keys::SessionKeys;
use crate::core::transcryption::contexts::{
    EncryptionContext, PseudonymizationDomain, TranscryptionInfo,
};
use crate::core::transcryption::secrets::EncryptionSecret;
use crate::core::transcryption::wasm::secrets::WASMPseudonymizationSecret;
use crate::core::wasm::keys::{
    WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey, WASMPseudonymSessionPublicKey,
    WASMPseudonymSessionSecretKey,
};
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

    /// Encrypt this PEPJSONValue into an EncryptedPEPJSONValue.
    ///
    /// # Arguments
    ///
    /// * `attribute_public_key` - Attribute session public key
    /// * `pseudonym_public_key` - Pseudonym session public key
    ///
    /// # Returns
    ///
    /// An EncryptedPEPJSONValue
    #[wasm_bindgen]
    pub fn encrypt(
        &self,
        attribute_public_key: &WASMAttributeSessionPublicKey,
        pseudonym_public_key: &WASMPseudonymSessionPublicKey,
    ) -> WASMEncryptedPEPJSONValue {
        let mut rng = rand::rng();

        let keys = SessionKeys {
            attribute: crate::core::keys::AttributeSessionKeys {
                public: (*attribute_public_key.0).into(),
                secret: ScalarNonZero::one().into(), // Dummy value, not needed for encryption
            },
            pseudonym: crate::core::keys::PseudonymSessionKeys {
                public: (*pseudonym_public_key.0).into(),
                secret: ScalarNonZero::one().into(), // Dummy value, not needed for encryption
            },
        };

        let encrypted = self.0.encrypt(&keys, &mut rng);
        WASMEncryptedPEPJSONValue(encrypted)
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
    /// Decrypt this EncryptedPEPJSONValue back into a regular JavaScript value.
    ///
    /// # Arguments
    ///
    /// * `attribute_secret_key` - Attribute session secret key
    /// * `pseudonym_secret_key` - Pseudonym session secret key
    ///
    /// # Returns
    ///
    /// A JavaScript value (object, array, string, number, boolean, or null)
    #[wasm_bindgen]
    pub fn decrypt(
        &self,
        attribute_secret_key: &WASMAttributeSessionSecretKey,
        pseudonym_secret_key: &WASMPseudonymSessionSecretKey,
    ) -> Result<JsValue, JsValue> {
        use crate::arithmetic::G;

        let keys = SessionKeys {
            attribute: crate::core::keys::AttributeSessionKeys {
                public: G.into(), // Dummy value, not needed for decryption
                secret: (*attribute_secret_key.0).into(),
            },
            pseudonym: crate::core::keys::PseudonymSessionKeys {
                public: G.into(), // Dummy value, not needed for decryption
                secret: (*pseudonym_secret_key.0).into(),
            },
        };

        let decrypted = self
            .0
            .decrypt(&keys)
            .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;

        serde_wasm_bindgen::to_value(&decrypted)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert to JS: {}", e)))
    }

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
        from_domain: &str,
        to_domain: &str,
        from_session: Option<String>,
        to_session: Option<String>,
        pseudonymization_secret: Option<WASMPseudonymizationSecret>,
        encryption_secret: Option<Vec<u8>>,
    ) -> Result<WASMEncryptedPEPJSONValue, JsValue> {
        let from_domain = PseudonymizationDomain::from(from_domain);
        let to_domain = PseudonymizationDomain::from(to_domain);
        let from_session_ctx = from_session.as_deref().map(EncryptionContext::from);
        let to_session_ctx = to_session.as_deref().map(EncryptionContext::from);

        let pseudo_secret = pseudonymization_secret.map(|s| s.0).unwrap_or_else(|| {
            crate::core::transcryption::secrets::PseudonymizationSecret::from(vec![])
        });

        let enc_secret = encryption_secret
            .map(EncryptionSecret::from)
            .unwrap_or_else(|| EncryptionSecret::from(vec![]));

        #[cfg(feature = "global")]
        let transcryption_info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            from_session_ctx.as_ref(),
            to_session_ctx.as_ref(),
            &pseudo_secret,
            &enc_secret,
        );

        #[cfg(not(feature = "global"))]
        let transcryption_info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            &from_session_ctx
                .ok_or_else(|| JsValue::from_str("from_session required without global feature"))?,
            &to_session_ctx
                .ok_or_else(|| JsValue::from_str("to_session required without global feature"))?,
            &pseudo_secret,
            &enc_secret,
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
    pub fn to_string(&self) -> String {
        format!("{:?}", self.0)
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
#[wasm_bindgen(js_name = PEPJSONBuilder)]
pub struct WASMPEPJSONBuilder {
    builder: PEPJSONBuilder,
}

#[wasm_bindgen(js_class = PEPJSONBuilder)]
impl WASMPEPJSONBuilder {
    /// Create a new builder.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            builder: PEPJSONBuilder::new(),
        }
    }

    /// Create a builder from a JavaScript object, marking specified fields as pseudonyms.
    ///
    /// # Arguments
    ///
    /// * `value` - A JavaScript object
    /// * `pseudonyms` - An array of field names that should be treated as pseudonyms
    ///
    /// # Returns
    ///
    /// A PEPJSONBuilder
    #[wasm_bindgen(js_name = fromObject)]
    pub fn from_object(
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

/// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
///
/// # Arguments
///
/// * `values` - Array of EncryptedPEPJSONValue objects
/// * `from_domain` - Source pseudonymization domain
/// * `to_domain` - Target pseudonymization domain
/// * `from_session` - Source encryption session (optional)
/// * `to_session` - Target encryption session (optional)
/// * `pseudonymization_secret` - Pseudonymization secret
/// * `encryption_secret` - Encryption secret
///
/// # Returns
///
/// A shuffled array of transcrypted EncryptedPEPJSONValue objects
#[wasm_bindgen(js_name = transcryptBatch)]
pub fn wasm_transcrypt_batch(
    values: Vec<WASMEncryptedPEPJSONValue>,
    from_domain: &str,
    to_domain: &str,
    from_session: Option<String>,
    to_session: Option<String>,
    pseudonymization_secret: Option<WASMPseudonymizationSecret>,
    encryption_secret: Option<Vec<u8>>,
) -> Result<Vec<WASMEncryptedPEPJSONValue>, JsValue> {
    let mut rng = rand::rng();

    let from_domain = PseudonymizationDomain::from(from_domain);
    let to_domain = PseudonymizationDomain::from(to_domain);
    let from_session_ctx = from_session.as_deref().map(EncryptionContext::from);
    let to_session_ctx = to_session.as_deref().map(EncryptionContext::from);

    let pseudo_secret = pseudonymization_secret.map(|s| s.0).unwrap_or_else(|| {
        crate::core::transcryption::secrets::PseudonymizationSecret::from(vec![])
    });

    let enc_secret = encryption_secret
        .map(EncryptionSecret::from)
        .unwrap_or_else(|| EncryptionSecret::from(vec![]));

    #[cfg(feature = "global")]
    let transcryption_info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        from_session_ctx.as_ref(),
        to_session_ctx.as_ref(),
        &pseudo_secret,
        &enc_secret,
    );

    #[cfg(not(feature = "global"))]
    let transcryption_info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        &from_session_ctx
            .ok_or_else(|| JsValue::from_str("from_session required without global feature"))?,
        &to_session_ctx
            .ok_or_else(|| JsValue::from_str("to_session required without global feature"))?,
        &pseudo_secret,
        &enc_secret,
    );

    let rust_values: Vec<EncryptedPEPJSONValue> = values.into_iter().map(|v| v.0).collect();
    let transcrypted = transcrypt_batch(rust_values, &transcryption_info, &mut rng);

    Ok(transcrypted
        .into_iter()
        .map(WASMEncryptedPEPJSONValue)
        .collect())
}
