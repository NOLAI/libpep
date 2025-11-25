use crate::core::data::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::core::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use crate::core::long::data::{
    decrypt_long_attribute, decrypt_long_pseudonym, encrypt_long_attribute, encrypt_long_pseudonym,
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use crate::core::wasm::data::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::core::wasm::keys::{
    WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey, WASMPseudonymSessionPublicKey,
    WASMPseudonymSessionSecretKey,
};
use derive_more::{Deref, From};
use wasm_bindgen::prelude::*;

/// A collection of pseudonyms that together represent a larger pseudonym value using PKCS#7 padding.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongPseudonym)]
pub struct WASMLongPseudonym(pub(crate) LongPseudonym);

#[wasm_bindgen(js_class = LongPseudonym)]
impl WASMLongPseudonym {
    /// Create from a vector of pseudonyms.
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonyms: Vec<WASMPseudonym>) -> Self {
        let rust_pseudonyms: Vec<Pseudonym> = pseudonyms.into_iter().map(|p| p.0).collect();
        Self(LongPseudonym(rust_pseudonyms))
    }

    /// Encodes an arbitrary-length string into a `LongPseudonym` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> WASMLongPseudonym {
        Self(LongPseudonym::from_string_padded(text))
    }

    /// Encodes an arbitrary-length byte array into a `LongPseudonym` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: &[u8]) -> WASMLongPseudonym {
        Self(LongPseudonym::from_bytes_padded(data))
    }

    /// Decodes the `LongPseudonym` back to the original string.
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Result<String, JsError> {
        self.0
            .to_string_padded()
            .map_err(|e| JsError::new(&format!("Decoding failed: {e}")))
    }

    /// Decodes the `LongPseudonym` back to the original byte array.
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Result<Vec<u8>, JsError> {
        self.0
            .to_bytes_padded()
            .map_err(|e| JsError::new(&format!("Decoding failed: {e}")))
    }

    /// Get the underlying pseudonyms.
    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMPseudonym> {
        self.0 .0.iter().map(|p| WASMPseudonym(*p)).collect()
    }

    /// Get the number of pseudonym blocks.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.0 .0.len()
    }

    /// Clone this object.
    #[wasm_bindgen(js_name = clone)]
    pub fn clone_js(&self) -> Self {
        self.clone()
    }
}

/// A collection of attributes that together represent a larger data value using PKCS#7 padding.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongAttribute)]
pub struct WASMLongAttribute(pub(crate) LongAttribute);

#[wasm_bindgen(js_class = LongAttribute)]
impl WASMLongAttribute {
    /// Create from a vector of attributes.
    #[wasm_bindgen(constructor)]
    pub fn new(attributes: Vec<WASMAttribute>) -> Self {
        let rust_attributes: Vec<Attribute> = attributes.into_iter().map(|a| a.0).collect();
        Self(LongAttribute(rust_attributes))
    }

    /// Encodes an arbitrary-length string into a `LongAttribute` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> WASMLongAttribute {
        Self(LongAttribute::from_string_padded(text))
    }

    /// Encodes an arbitrary-length byte array into a `LongAttribute` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: &[u8]) -> WASMLongAttribute {
        Self(LongAttribute::from_bytes_padded(data))
    }

    /// Decodes the `LongAttribute` back to the original string.
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Result<String, JsError> {
        self.0
            .to_string_padded()
            .map_err(|e| JsError::new(&format!("Decoding failed: {e}")))
    }

    /// Decodes the `LongAttribute` back to the original byte array.
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Result<Vec<u8>, JsError> {
        self.0
            .to_bytes_padded()
            .map_err(|e| JsError::new(&format!("Decoding failed: {e}")))
    }

    /// Get the underlying attributes.
    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMAttribute> {
        self.0 .0.iter().map(|a| WASMAttribute(*a)).collect()
    }

    /// Get the number of attribute blocks.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.0 .0.len()
    }

    /// Clone this object.
    #[wasm_bindgen(js_name = clone)]
    pub fn clone_js(&self) -> Self {
        self.clone()
    }
}

/// A collection of encrypted pseudonyms that can be serialized as a pipe-delimited string.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongEncryptedPseudonym)]
pub struct WASMLongEncryptedPseudonym(pub(crate) LongEncryptedPseudonym);

#[wasm_bindgen(js_class = LongEncryptedPseudonym)]
impl WASMLongEncryptedPseudonym {
    /// Create from a vector of encrypted pseudonyms.
    #[wasm_bindgen(constructor)]
    pub fn new(encrypted_pseudonyms: Vec<WASMEncryptedPseudonym>) -> Self {
        let rust_enc_pseudonyms: Vec<EncryptedPseudonym> =
            encrypted_pseudonyms.into_iter().map(|p| p.0).collect();
        Self(LongEncryptedPseudonym(rust_enc_pseudonyms))
    }

    /// Serializes to a pipe-delimited base64 string.
    #[wasm_bindgen]
    pub fn serialize(&self) -> String {
        self.0.serialize()
    }

    /// Deserializes from a pipe-delimited base64 string.
    #[wasm_bindgen]
    pub fn deserialize(s: &str) -> Result<WASMLongEncryptedPseudonym, JsError> {
        LongEncryptedPseudonym::deserialize(s)
            .map(Self)
            .map_err(|e| JsError::new(&format!("Deserialization failed: {e}")))
    }

    /// Get the underlying encrypted pseudonyms.
    #[wasm_bindgen(getter, js_name = encryptedPseudonyms)]
    pub fn encrypted_pseudonyms(&self) -> Vec<WASMEncryptedPseudonym> {
        self.0
             .0
            .iter()
            .map(|p| WASMEncryptedPseudonym(*p))
            .collect()
    }

    /// Get the number of encrypted pseudonym blocks.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.0 .0.len()
    }

    /// Clone this object.
    #[wasm_bindgen(js_name = clone)]
    pub fn clone_js(&self) -> Self {
        self.clone()
    }
}

/// A collection of encrypted attributes that can be serialized as a pipe-delimited string.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongEncryptedAttribute)]
pub struct WASMLongEncryptedAttribute(pub(crate) LongEncryptedAttribute);

#[wasm_bindgen(js_class = LongEncryptedAttribute)]
impl WASMLongEncryptedAttribute {
    /// Create from a vector of encrypted attributes.
    #[wasm_bindgen(constructor)]
    pub fn new(encrypted_attributes: Vec<WASMEncryptedAttribute>) -> Self {
        let rust_enc_attributes: Vec<EncryptedAttribute> =
            encrypted_attributes.into_iter().map(|a| a.0).collect();
        Self(LongEncryptedAttribute(rust_enc_attributes))
    }

    /// Serializes to a pipe-delimited base64 string.
    #[wasm_bindgen]
    pub fn serialize(&self) -> String {
        self.0.serialize()
    }

    /// Deserializes from a pipe-delimited base64 string.
    #[wasm_bindgen]
    pub fn deserialize(s: &str) -> Result<WASMLongEncryptedAttribute, JsError> {
        LongEncryptedAttribute::deserialize(s)
            .map(Self)
            .map_err(|e| JsError::new(&format!("Deserialization failed: {e}")))
    }

    /// Get the underlying encrypted attributes.
    #[wasm_bindgen(getter, js_name = encryptedAttributes)]
    pub fn encrypted_attributes(&self) -> Vec<WASMEncryptedAttribute> {
        self.0
             .0
            .iter()
            .map(|a| WASMEncryptedAttribute(*a))
            .collect()
    }

    /// Get the number of encrypted attribute blocks.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.0 .0.len()
    }

    /// Clone this object.
    #[wasm_bindgen(js_name = clone)]
    pub fn clone_js(&self) -> Self {
        self.clone()
    }
}

/// Encrypt a long pseudonym.
#[wasm_bindgen(js_name = encryptLongPseudonym)]
pub fn wasm_encrypt_long_pseudonym(
    message: &WASMLongPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    WASMLongEncryptedPseudonym(encrypt_long_pseudonym(
        &message.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt a long encrypted pseudonym.
#[wasm_bindgen(js_name = decryptLongPseudonym)]
#[cfg(feature = "elgamal3")]
pub fn wasm_decrypt_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> Option<WASMLongPseudonym> {
    decrypt_long_pseudonym(
        &encrypted.0,
        &PseudonymSessionSecretKey::from(secret_key.0 .0),
    )
    .map(WASMLongPseudonym)
}

/// Decrypt a long encrypted pseudonym.
#[wasm_bindgen(js_name = decryptLongPseudonym)]
#[cfg(not(feature = "elgamal3"))]
pub fn wasm_decrypt_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> WASMLongPseudonym {
    WASMLongPseudonym(decrypt_long_pseudonym(
        &encrypted.0,
        &PseudonymSessionSecretKey::from(secret_key.0 .0),
    ))
}

/// Encrypt a long attribute.
#[wasm_bindgen(js_name = encryptLongAttribute)]
pub fn wasm_encrypt_long_attribute(
    message: &WASMLongAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    WASMLongEncryptedAttribute(encrypt_long_attribute(
        &message.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt a long encrypted attribute.
#[wasm_bindgen(js_name = decryptLongAttribute)]
#[cfg(feature = "elgamal3")]
pub fn wasm_decrypt_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> Option<WASMLongAttribute> {
    decrypt_long_attribute(
        &encrypted.0,
        &AttributeSessionSecretKey::from(secret_key.0 .0),
    )
    .map(WASMLongAttribute)
}

/// Decrypt a long encrypted attribute.
#[wasm_bindgen(js_name = decryptLongAttribute)]
#[cfg(not(feature = "elgamal3"))]
pub fn wasm_decrypt_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> WASMLongAttribute {
    WASMLongAttribute(decrypt_long_attribute(
        &encrypted.0,
        &AttributeSessionSecretKey::from(secret_key.0 .0),
    ))
}
