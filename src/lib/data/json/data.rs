//! Core JSON encryption types and implementations.

use super::utils::{bool_to_byte, byte_to_bool, bytes_to_number, number_to_bytes};
use crate::arithmetic::scalars::ScalarNonZero;
#[cfg(feature = "long")]
use crate::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use crate::data::padding::Padded;
use crate::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::data::traits::{Encryptable, Encrypted, Transcryptable};
use crate::factors::RerandomizeFactor;
use crate::factors::TranscryptionInfo;
#[cfg(feature = "offline")]
use crate::keys::GlobalPublicKeys;
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::GlobalSecretKeys;
use crate::keys::SessionKeys;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum JsonError {
    #[error("invalid boolean byte value: 0x{got:02x}. expected 0x00 or 0x01")]
    InvalidBoolByte { got: u8 },

    #[error("expected 1 byte for bool, got {got}")]
    BoolBytesWrongLen { got: usize },

    #[error("expected 9 bytes for number, got {got}")]
    NumberBytesWrongLen { got: usize },

    #[error("failed to decode bool: {0}")]
    BoolDecode(String),

    #[error("failed to get bytes from bool: {0}")]
    BoolPadding(String),

    #[error("failed to get bytes from number: {0}")]
    NumberPadding(String),

    #[error("failed to parse string: {0}")]
    StringPadding(String),
}
/// A JSON value where primitive types are stored as unencrypted PEP types.
///
/// - `Null` remains as-is
/// - `Bool` is stored as a single `Attribute` (1 byte)
/// - `Number` is stored as a single `Attribute` (9 bytes: 1 byte type tag + 8 bytes data for u64/i64/f64)
/// - `String` is stored as a `LongAttribute` (variable length)
/// - `Pseudonym` is stored as a `LongPseudonym` (can be pseudonymized/reshuffled)
/// - `Array` and `Object` contain nested `PEPJSONValue`s
///
/// Call `.encrypt()` to convert this into an `EncryptedPEPJSONValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PEPJSONValue {
    Null,
    Bool(Attribute),
    Number(Attribute),
    /// Short string that fits in a single block (≤15 bytes)
    String(Attribute),
    /// Long string that requires multiple blocks
    LongString(LongAttribute),
    /// Short pseudonym from 32-byte value
    Pseudonym(Pseudonym),
    /// Long pseudonym (multiple 32-byte values or lizard-encoded)
    LongPseudonym(LongPseudonym),
    Array(Vec<PEPJSONValue>),
    Object(HashMap<String, PEPJSONValue>),
}

/// An encrypted JSON value where primitive types are encrypted as PEP types.
///
/// - `Null` remains unencrypted
/// - `Bool` is encrypted as a single `EncryptedAttribute` (1 byte)
/// - `Number` is encrypted as a single `EncryptedAttribute` (9 bytes: 1 byte type tag + 8 bytes data for u64/i64/f64)
/// - `String` is encrypted as a `LongEncryptedAttribute` (variable length)
/// - `Pseudonym` is encrypted as a `LongEncryptedPseudonym` (can be pseudonymized/reshuffled)
/// - `Array` and `Object` contain nested `EncryptedPEPJSONValue`s
///
/// Call `.decrypt()` to convert this back into a regular `serde_json::Value`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "data"))]
pub enum EncryptedPEPJSONValue {
    Null,
    Bool(EncryptedAttribute),
    Number(EncryptedAttribute),
    /// Short string that fits in a single block (≤15 bytes)
    String(EncryptedAttribute),
    /// Long string that requires multiple blocks
    LongString(LongEncryptedAttribute),
    /// Short pseudonym from 32-byte value
    Pseudonym(EncryptedPseudonym),
    /// Long pseudonym (multiple 32-byte values or lizard-encoded)
    LongPseudonym(LongEncryptedPseudonym),
    Array(Vec<EncryptedPEPJSONValue>),
    Object(HashMap<String, EncryptedPEPJSONValue>),
}

impl PEPJSONValue {
    /// Convert this PEPJSONValue back to a regular JSON Value.
    ///
    /// This extracts the underlying data from unencrypted PEP types.
    pub fn to_value(&self) -> Result<Value, JsonError> {
        match self {
            Self::Null => Ok(Value::Null),
            Self::Bool(attr) => {
                let bytes = attr
                    .to_bytes_padded()
                    .map_err(|e| JsonError::BoolPadding(format!("{e:?}")))?;
                let b = *bytes
                    .first()
                    .ok_or(JsonError::BoolBytesWrongLen { got: 0 })?;
                if bytes.len() != 1 {
                    return Err(JsonError::BoolBytesWrongLen { got: bytes.len() });
                }
                let bool_val = byte_to_bool(b).map_err(|e| JsonError::BoolDecode(e.to_string()))?;
                Ok(Value::Bool(bool_val))
            }
            Self::Number(attr) => {
                let bytes = attr
                    .to_bytes_padded()
                    .map_err(|e| JsonError::NumberPadding(format!("{e:?}")))?;
                let arr: [u8; 9] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| JsonError::NumberBytesWrongLen { got: bytes.len() })?;
                let num_val = bytes_to_number(&arr);
                Ok(Value::Number(num_val))
            }
            Self::String(attr) => {
                let string_val = attr
                    .to_string_padded()
                    .map_err(|e| JsonError::StringPadding(format!("{e:?}")))?;
                Ok(Value::String(string_val))
            }
            Self::LongString(attr) => {
                let string_val = attr
                    .to_string_padded()
                    .map_err(|e| JsonError::StringPadding(format!("{e:?}")))?;
                Ok(Value::String(string_val))
            }
            Self::Pseudonym(pseudo) => {
                let string_val = pseudo
                    .to_string_padded()
                    .unwrap_or_else(|_| pseudo.to_hex());
                Ok(Value::String(string_val))
            }
            Self::LongPseudonym(pseudo) => {
                let string_val = pseudo
                    .to_string_padded()
                    .unwrap_or_else(|_| pseudo.to_hex());
                Ok(Value::String(string_val))
            }
            Self::Array(arr) => {
                let json_arr = arr
                    .iter()
                    .map(Self::to_value)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Value::Array(json_arr))
            }
            Self::Object(obj) => {
                let json_obj = obj
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), v.to_value()?)))
                    .collect::<Result<serde_json::Map<String, Value>, JsonError>>()?;
                Ok(Value::Object(json_obj))
            }
        }
    }

    /// Create a PEPJSONValue from a regular JSON Value.
    ///
    /// This converts JSON primitives into unencrypted PEP types.
    /// This method never fails for valid serde_json Values.
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(b) => {
                let byte = bool_to_byte(*b);
                // Safety: 1 byte always fits in a 16-byte block with PKCS#7 padding
                #[allow(clippy::expect_used)]
                let attr = Attribute::from_bytes_padded(&[byte])
                    .expect("1 byte always fits in 16-byte block");
                Self::Bool(attr)
            }
            Value::Number(n) => {
                let bytes = number_to_bytes(n);
                // Safety: 9 bytes always fits in a 16-byte block with PKCS#7 padding
                #[allow(clippy::expect_used)]
                let attr = Attribute::from_bytes_padded(&bytes)
                    .expect("9 bytes always fits in 16-byte block");
                Self::Number(attr)
            }
            Value::String(s) => {
                // Check if string fits in a single block (≤15 bytes with PKCS#7 padding)
                if s.len() <= 15 {
                    // Try to create a short string
                    match Attribute::from_string_padded(s) {
                        Ok(attr) => Self::String(attr),
                        Err(_) => Self::LongString(LongAttribute::from_string_padded(s)),
                    }
                } else {
                    // Use long string for strings > 15 bytes
                    Self::LongString(LongAttribute::from_string_padded(s))
                }
            }
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                out.extend(arr.iter().map(Self::from_value));
                Self::Array(out)
            }
            Value::Object(obj) => {
                let mut out = HashMap::with_capacity(obj.len());
                out.extend(obj.iter().map(|(k, v)| (k.clone(), Self::from_value(v))));
                Self::Object(out)
            }
        }
    }
}

impl Encryptable for PEPJSONValue {
    type EncryptedType = EncryptedPEPJSONValue;
    type PublicKeyType = SessionKeys;

    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = GlobalPublicKeys;

    fn encrypt<R: RngCore + CryptoRng>(
        &self,
        keys: &Self::PublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType {
        match self {
            PEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            PEPJSONValue::Bool(attr) => {
                EncryptedPEPJSONValue::Bool(attr.encrypt(&keys.attribute.public, rng))
            }
            PEPJSONValue::Number(attr) => {
                EncryptedPEPJSONValue::Number(attr.encrypt(&keys.attribute.public, rng))
            }
            PEPJSONValue::String(attr) => {
                EncryptedPEPJSONValue::String(attr.encrypt(&keys.attribute.public, rng))
            }
            PEPJSONValue::LongString(long_attr) => {
                EncryptedPEPJSONValue::LongString(long_attr.encrypt(&keys.attribute.public, rng))
            }
            PEPJSONValue::Pseudonym(pseudo) => {
                EncryptedPEPJSONValue::Pseudonym(pseudo.encrypt(&keys.pseudonym.public, rng))
            }
            PEPJSONValue::LongPseudonym(long_pseudo) => EncryptedPEPJSONValue::LongPseudonym(
                long_pseudo.encrypt(&keys.pseudonym.public, rng),
            ),
            PEPJSONValue::Array(arr) => EncryptedPEPJSONValue::Array(
                arr.iter().map(|item| item.encrypt(keys, rng)).collect(),
            ),
            PEPJSONValue::Object(obj) => EncryptedPEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.encrypt(keys, rng)))
                    .collect(),
            ),
        }
    }
    #[cfg(feature = "offline")]
    fn encrypt_global<R: RngCore + CryptoRng>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType {
        match self {
            PEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            PEPJSONValue::Bool(attr) => {
                EncryptedPEPJSONValue::Bool(attr.encrypt_global(&public_key.attribute, rng))
            }
            PEPJSONValue::Number(attr) => {
                EncryptedPEPJSONValue::Number(attr.encrypt_global(&public_key.attribute, rng))
            }
            PEPJSONValue::String(attr) => {
                EncryptedPEPJSONValue::String(attr.encrypt_global(&public_key.attribute, rng))
            }
            PEPJSONValue::LongString(long_attr) => EncryptedPEPJSONValue::LongString(
                long_attr.encrypt_global(&public_key.attribute, rng),
            ),
            PEPJSONValue::Pseudonym(pseudo) => {
                EncryptedPEPJSONValue::Pseudonym(pseudo.encrypt_global(&public_key.pseudonym, rng))
            }
            PEPJSONValue::LongPseudonym(long_pseudo) => EncryptedPEPJSONValue::LongPseudonym(
                long_pseudo.encrypt_global(&public_key.pseudonym, rng),
            ),
            PEPJSONValue::Array(arr) => EncryptedPEPJSONValue::Array(
                arr.iter()
                    .map(|item| item.encrypt_global(public_key, rng))
                    .collect(),
            ),
            PEPJSONValue::Object(obj) => EncryptedPEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.encrypt_global(public_key, rng)))
                    .collect(),
            ),
        }
    }
}

impl Encrypted for EncryptedPEPJSONValue {
    type UnencryptedType = PEPJSONValue;
    type SecretKeyType = SessionKeys;

    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = GlobalSecretKeys;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        match self {
            EncryptedPEPJSONValue::Null => Some(PEPJSONValue::Null),
            EncryptedPEPJSONValue::Bool(enc) => {
                Some(PEPJSONValue::Bool(enc.decrypt(&keys.attribute.secret)?))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                Some(PEPJSONValue::Number(enc.decrypt(&keys.attribute.secret)?))
            }
            EncryptedPEPJSONValue::String(enc) => {
                Some(PEPJSONValue::String(enc.decrypt(&keys.attribute.secret)?))
            }
            EncryptedPEPJSONValue::LongString(enc) => Some(PEPJSONValue::LongString(
                enc.decrypt(&keys.attribute.secret)?,
            )),
            EncryptedPEPJSONValue::Pseudonym(enc) => Some(PEPJSONValue::Pseudonym(
                enc.decrypt(&keys.pseudonym.secret)?,
            )),
            EncryptedPEPJSONValue::LongPseudonym(enc) => Some(PEPJSONValue::LongPseudonym(
                enc.decrypt(&keys.pseudonym.secret)?,
            )),
            EncryptedPEPJSONValue::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(item.decrypt(keys)?);
                }
                Some(PEPJSONValue::Array(out))
            }
            EncryptedPEPJSONValue::Object(obj) => {
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    out.insert(k.clone(), v.decrypt(keys)?);
                }
                Some(PEPJSONValue::Object(out))
            }
        }
    }
    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Self::UnencryptedType {
        match self {
            EncryptedPEPJSONValue::Null => PEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                PEPJSONValue::Bool(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                PEPJSONValue::Number(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPEPJSONValue::String(enc) => {
                PEPJSONValue::String(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPEPJSONValue::LongString(enc) => {
                PEPJSONValue::LongString(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => {
                PEPJSONValue::Pseudonym(enc.decrypt(&keys.pseudonym.secret))
            }
            EncryptedPEPJSONValue::LongPseudonym(enc) => {
                PEPJSONValue::LongPseudonym(enc.decrypt(&keys.pseudonym.secret))
            }
            EncryptedPEPJSONValue::Array(arr) => {
                PEPJSONValue::Array(arr.iter().map(|x| x.decrypt(keys)).collect())
            }
            EncryptedPEPJSONValue::Object(obj) => PEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.decrypt(keys)))
                    .collect(),
            ),
        }
    }

    // Global decryption for offline+insecure+elgamal3
    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        match self {
            EncryptedPEPJSONValue::Null => Some(PEPJSONValue::Null),
            EncryptedPEPJSONValue::Bool(enc) => Some(PEPJSONValue::Bool(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPEPJSONValue::Number(enc) => Some(PEPJSONValue::Number(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPEPJSONValue::String(enc) => Some(PEPJSONValue::String(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPEPJSONValue::LongString(enc) => Some(PEPJSONValue::LongString(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPEPJSONValue::Pseudonym(enc) => Some(PEPJSONValue::Pseudonym(
                enc.decrypt_global(&secret_key.pseudonym)?,
            )),
            EncryptedPEPJSONValue::LongPseudonym(enc) => Some(PEPJSONValue::LongPseudonym(
                enc.decrypt_global(&secret_key.pseudonym)?,
            )),
            EncryptedPEPJSONValue::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(item.decrypt_global(secret_key)?);
                }
                Some(PEPJSONValue::Array(out))
            }
            EncryptedPEPJSONValue::Object(obj) => {
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    out.insert(k.clone(), v.decrypt_global(secret_key)?);
                }
                Some(PEPJSONValue::Object(out))
            }
        }
    }

    // Global decryption for offline+insecure (no elgamal3)
    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        match self {
            EncryptedPEPJSONValue::Null => PEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                PEPJSONValue::Bool(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                PEPJSONValue::Number(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPEPJSONValue::String(enc) => {
                PEPJSONValue::String(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPEPJSONValue::LongString(enc) => {
                PEPJSONValue::LongString(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => {
                PEPJSONValue::Pseudonym(enc.decrypt_global(&secret_key.pseudonym))
            }
            EncryptedPEPJSONValue::LongPseudonym(enc) => {
                PEPJSONValue::LongPseudonym(enc.decrypt_global(&secret_key.pseudonym))
            }
            EncryptedPEPJSONValue::Array(arr) => {
                PEPJSONValue::Array(arr.iter().map(|x| x.decrypt_global(secret_key)).collect())
            }
            EncryptedPEPJSONValue::Object(obj) => PEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.decrypt_global(secret_key)))
                    .collect(),
            ),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor) -> Self {
        match self {
            EncryptedPEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                EncryptedPEPJSONValue::Bool(enc.rerandomize_known(factor))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                EncryptedPEPJSONValue::Number(enc.rerandomize_known(factor))
            }
            EncryptedPEPJSONValue::String(enc) => {
                EncryptedPEPJSONValue::String(enc.rerandomize_known(factor))
            }
            EncryptedPEPJSONValue::LongString(enc) => {
                EncryptedPEPJSONValue::LongString(enc.rerandomize_known(factor))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => {
                EncryptedPEPJSONValue::Pseudonym(enc.rerandomize_known(factor))
            }
            EncryptedPEPJSONValue::LongPseudonym(enc) => {
                EncryptedPEPJSONValue::LongPseudonym(enc.rerandomize_known(factor))
            }
            EncryptedPEPJSONValue::Array(arr) => EncryptedPEPJSONValue::Array(
                arr.iter().map(|x| x.rerandomize_known(factor)).collect(),
            ),
            EncryptedPEPJSONValue::Object(obj) => EncryptedPEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.rerandomize_known(factor)))
                    .collect(),
            ),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor,
    ) -> Self {
        match self {
            EncryptedPEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => EncryptedPEPJSONValue::Bool(
                enc.rerandomize_known(&public_key.attribute.public, factor),
            ),
            EncryptedPEPJSONValue::Number(enc) => EncryptedPEPJSONValue::Number(
                enc.rerandomize_known(&public_key.attribute.public, factor),
            ),
            EncryptedPEPJSONValue::String(enc) => EncryptedPEPJSONValue::String(
                enc.rerandomize_known(&public_key.attribute.public, factor),
            ),
            EncryptedPEPJSONValue::LongString(enc) => EncryptedPEPJSONValue::LongString(
                enc.rerandomize_known(&public_key.attribute.public, factor),
            ),
            EncryptedPEPJSONValue::Pseudonym(enc) => EncryptedPEPJSONValue::Pseudonym(
                enc.rerandomize_known(&public_key.pseudonym.public, factor),
            ),
            EncryptedPEPJSONValue::LongPseudonym(enc) => EncryptedPEPJSONValue::LongPseudonym(
                enc.rerandomize_known(&public_key.pseudonym.public, factor),
            ),
            EncryptedPEPJSONValue::Array(arr) => EncryptedPEPJSONValue::Array(
                arr.iter()
                    .map(|x| x.rerandomize_known(public_key, factor))
                    .collect(),
            ),
            EncryptedPEPJSONValue::Object(obj) => EncryptedPEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.rerandomize_known(public_key, factor)))
                    .collect(),
            ),
        }
    }
}

// Transcryption trait implementation for JSON

impl Transcryptable for EncryptedPEPJSONValue {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        match self {
            EncryptedPEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => EncryptedPEPJSONValue::Bool(enc.transcrypt(info)),
            EncryptedPEPJSONValue::Number(enc) => {
                EncryptedPEPJSONValue::Number(enc.transcrypt(info))
            }
            EncryptedPEPJSONValue::String(enc) => {
                EncryptedPEPJSONValue::String(enc.transcrypt(info))
            }
            EncryptedPEPJSONValue::LongString(enc) => {
                EncryptedPEPJSONValue::LongString(enc.transcrypt(info))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => {
                EncryptedPEPJSONValue::Pseudonym(enc.transcrypt(info))
            }
            EncryptedPEPJSONValue::LongPseudonym(enc) => {
                EncryptedPEPJSONValue::LongPseudonym(enc.transcrypt(info))
            }
            EncryptedPEPJSONValue::Array(arr) => {
                EncryptedPEPJSONValue::Array(arr.iter().map(|x| x.transcrypt(info)).collect())
            }
            EncryptedPEPJSONValue::Object(obj) => EncryptedPEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.transcrypt(info)))
                    .collect(),
            ),
        }
    }
}

#[cfg(feature = "batch")]
impl crate::data::traits::HasStructure for EncryptedPEPJSONValue {
    type Structure = super::structure::JSONStructure;

    fn structure(&self) -> Self::Structure {
        self.structure()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::{decrypt, encrypt};
    use crate::factors::contexts::EncryptionContext;
    use crate::factors::EncryptionSecret;
    use crate::keys::{
        make_attribute_global_keys, make_attribute_session_keys, make_pseudonym_global_keys,
        make_pseudonym_session_keys, AttributeSessionKeys, PseudonymSessionKeys, SessionKeys,
    };
    use serde_json::json;

    fn make_test_keys() -> SessionKeys {
        let mut rng = rand::rng();
        let (_, attr_global_secret) = make_attribute_global_keys(&mut rng);
        let (_, pseudo_global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");

        let (attr_public, attr_secret) =
            make_attribute_session_keys(&attr_global_secret, &session, &enc_secret);
        let (pseudo_public, pseudo_secret) =
            make_pseudonym_session_keys(&pseudo_global_secret, &session, &enc_secret);

        SessionKeys {
            attribute: AttributeSessionKeys {
                public: attr_public,
                secret: attr_secret,
            },
            pseudonym: PseudonymSessionKeys {
                public: pseudo_public,
                secret: pseudo_secret,
            },
        }
    }

    #[test]
    fn encrypt_decrypt_null() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!(null);
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        assert_eq!(value, decrypted.to_value().unwrap());
    }

    #[test]
    fn encrypt_decrypt_bool() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        for b in [true, false] {
            let value = json!(b);
            let pep_value = PEPJSONValue::from_value(&value);
            let encrypted = encrypt(&pep_value, &keys, &mut rng);
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt(&encrypted, &keys).unwrap();

            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt(&encrypted, &keys);
            assert_eq!(value, decrypted.to_value().unwrap());
        }
    }

    #[test]
    fn encrypt_decrypt_number() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let test_numbers = [0, 1, -1, 42, -42, i64::MAX, i64::MIN];
        for n in test_numbers {
            let value = json!(n);
            let pep_value = PEPJSONValue::from_value(&value);
            let encrypted = encrypt(&pep_value, &keys, &mut rng);
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt(&encrypted, &keys).unwrap();

            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt(&encrypted, &keys);
            assert_eq!(value, decrypted.to_value().unwrap());
        }

        // Test floats
        let test_floats = [0.0, 1.5, -1.5, 37.2, 38.5, 42.42, f64::MAX, f64::MIN];
        for f in test_floats {
            let value = json!(f);
            let pep_value = PEPJSONValue::from_value(&value);
            let encrypted = encrypt(&pep_value, &keys, &mut rng);
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt(&encrypted, &keys).unwrap();

            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt(&encrypted, &keys);
            assert_eq!(value, decrypted.to_value().unwrap());
        }
    }

    #[test]
    fn encrypt_decrypt_string() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let test_strings = [
            "",
            "hello",
            "Hello, world!",
            "A longer string that spans multiple blocks of 16 bytes each",
        ];
        for s in test_strings {
            let value = json!(s);
            let pep_value = PEPJSONValue::from_value(&value);
            let encrypted = encrypt(&pep_value, &keys, &mut rng);
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt(&encrypted, &keys).unwrap();

            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt(&encrypted, &keys);
            assert_eq!(value, decrypted.to_value().unwrap());
        }
    }

    #[test]
    fn encrypt_decrypt_array() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!([true, 42, "hello", null]);
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        assert_eq!(value, decrypted.to_value().unwrap());
    }

    #[test]
    fn encrypt_decrypt_object() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!({
            "name": "Alice",
            "age": 30,
            "active": true,
            "email": null
        });
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        assert_eq!(value, decrypted.to_value().unwrap());
    }

    #[test]
    fn encrypt_decrypt_nested() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!({
            "users": [
                {
                    "name": "Alice",
                    "scores": [95, 87, 92]
                },
                {
                    "name": "Bob",
                    "scores": [88, 91, 85]
                }
            ],
            "metadata": {
                "version": 1,
                "active": true
            }
        });
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        assert_eq!(value, decrypted.to_value().unwrap());
    }

    #[test]
    fn unicode_strings() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let test_strings = ["café", "你好世界", "🎉🎊🎁"];
        for s in test_strings {
            let value = json!(s);
            let pep_value = PEPJSONValue::from_value(&value);
            let encrypted = encrypt(&pep_value, &keys, &mut rng);
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt(&encrypted, &keys).unwrap();

            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt(&encrypted, &keys);
            assert_eq!(value, decrypted.to_value().unwrap());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!({
            "test": "value",
            "number": 123
        });
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = encrypt(&pep_value, &keys, &mut rng);

        let json_str = serde_json::to_string(&encrypted).expect("serialization should succeed");
        let deserialized: EncryptedPEPJSONValue =
            serde_json::from_str(&json_str).expect("deserialization should succeed");

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&deserialized, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&deserialized, &keys);
        assert_eq!(value, decrypted.to_value().unwrap());
    }

    #[test]
    fn mixed_attributes_and_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        use crate::pep_json;

        let pep_value = pep_json!({
            "id": pseudonym("user-123"),
            "name": "Alice",
            "age": 30
        });
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        let expected = json!({
            "id": "user-123",
            "name": "Alice",
            "age": 30
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    /// Example: Encrypt a user profile where the ID is a pseudonym (can be reshuffled)
    /// and other fields are regular attributes.
    ///
    /// This demonstrates how to represent:
    /// ```json
    /// {
    ///     "id": "user1@example.com",
    ///     "age": 16,
    ///     "verified": true,
    ///     "scores": [88, 91, 85]
    /// }
    /// ```
    /// where "id" is encrypted as a pseudonym for later pseudonymization.
    #[test]
    fn user_profile_with_pseudonym_id() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        use crate::pep_json;

        let pep_value = pep_json!({
            "id": pseudonym("user1@example.com"),
            "age": 16,
            "verified": true,
            "scores": [88, 91, 85]
        });
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        let expected = json!({
            "id": "user1@example.com",
            "age": 16,
            "verified": true,
            "scores": [88, 91, 85]
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    #[test]
    fn test_equality_traits() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Test PEPJSONValue equality
        let value1 = json!({"name": "Alice", "age": 30});
        let pep_value1 = PEPJSONValue::from_value(&value1);
        let pep_value2 = PEPJSONValue::from_value(&value1);
        assert_eq!(pep_value1, pep_value2);

        // Test different values are not equal
        let value2 = json!({"name": "Bob", "age": 25});
        let pep_value3 = PEPJSONValue::from_value(&value2);
        assert_ne!(pep_value1, pep_value3);

        // Test EncryptedPEPJSONValue equality (same plaintext encrypts to different ciphertexts)
        let encrypted1 = encrypt(&pep_value1, &keys, &mut rng);
        let encrypted2 = encrypt(&pep_value1, &keys, &mut rng);
        // Different encryptions of same plaintext should NOT be equal due to randomness
        assert_ne!(encrypted1, encrypted2);

        // Test that decrypted values are equal
        #[cfg(feature = "elgamal3")]
        let decrypted1 = decrypt(&encrypted1, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted1 = decrypt(&encrypted1, &keys);
        #[cfg(feature = "elgamal3")]
        let decrypted2 = decrypt(&encrypted2, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted2 = decrypt(&encrypted2, &keys);
        assert_eq!(decrypted1, decrypted2);
    }
}
