//! JSON encryption types generic over the [`Group`](crate::elgamal::arithmetic::Group), which must have an [`InvertibleEncoding`]
//! for the attribute values.

use crate::data::json::data::JsonError;
#[cfg(feature = "batch")]
use crate::data::json::unify_structures;
use crate::data::json::utils::{bool_to_byte, byte_to_bool, bytes_to_number, number_to_bytes};
#[cfg(feature = "long")]
use crate::data::long::generic::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use crate::data::padding::Padded;
use crate::data::simple::generic::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::data::simple::ElGamalEncryptable;
#[cfg(feature = "batch")]
use crate::data::traits::BatchEncryptable;
use crate::data::traits::{Encryptable, Encrypted, Transcryptable};
use crate::elgamal::arithmetic::group::InvertibleEncoding;
#[cfg(feature = "batch")]
use crate::errors::BatchError;
use crate::factors::types::generic::{RerandomizeFactor, TranscryptionInfo};
#[cfg(feature = "offline")]
use crate::keys::types::generic::GlobalPublicKeys;
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::generic::GlobalSecretKeys;
use crate::keys::types::generic::{SessionKeys, SessionPublicKeys};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

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
pub enum PEPJSONValue<G: InvertibleEncoding> {
    Null,
    Bool(Attribute<G>),
    Number(Attribute<G>),
    /// Short string that fits in a single block (≤15 bytes)
    String(Attribute<G>),
    /// Long string that requires multiple blocks
    LongString(LongAttribute<G>),
    /// Short pseudonym from 32-byte value
    Pseudonym(Pseudonym<G>),
    /// Long pseudonym (multiple 32-byte values or lizard-encoded)
    LongPseudonym(LongPseudonym<G>),
    Array(Vec<PEPJSONValue<G>>),
    Object(HashMap<String, PEPJSONValue<G>>),
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "data"))]
pub enum EncryptedPEPJSONValue<G: InvertibleEncoding> {
    Null,
    Bool(EncryptedAttribute<G>),
    Number(EncryptedAttribute<G>),
    /// Short string that fits in a single block (≤15 bytes)
    String(EncryptedAttribute<G>),
    /// Long string that requires multiple blocks
    LongString(LongEncryptedAttribute<G>),
    /// Short pseudonym from 32-byte value
    Pseudonym(EncryptedPseudonym<G>),
    /// Long pseudonym (multiple 32-byte values or lizard-encoded)
    LongPseudonym(LongEncryptedPseudonym<G>),
    Array(Vec<EncryptedPEPJSONValue<G>>),
    Object(HashMap<String, EncryptedPEPJSONValue<G>>),
}

impl<G: InvertibleEncoding> PEPJSONValue<G> {
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
                let num_val = bytes_to_number(&arr)?;
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

    /// Pads this PEPJSONValue to match a target structure by adding external padding blocks.
    ///
    /// This method adds external padding blocks (separate from any internal PKCS#7-style
    /// padding used inside individual ciphertext blocks) to `LongString` and
    /// `LongPseudonym` variants to ensure all instances have the same number of blocks
    /// when encrypted. This is necessary for batch transcryption where all encrypted values must
    /// have identical structure to prevent linkability.
    ///
    /// The external padding blocks are all-zero blocks `[0x00, 0x00, ...]` that contain no user data.
    /// These padding blocks are automatically detected and removed during decoding,
    /// ensuring the original values are perfectly preserved.
    ///
    /// # Parameters
    ///
    /// - `structure`: The target structure specifying the number of blocks for each field
    ///
    /// # Returns
    ///
    /// Returns a padded `PEPJSONValue` with padding blocks added where necessary.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The current structure doesn't match the target structure type
    /// - The current size exceeds the target size (cannot pad by removing blocks)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::json::data::PEPJSONValue;
    /// use libpep::data::json::structure::JSONStructure;
    /// use serde_json::json;
    ///
    /// let value1 = PEPJSONValue::from_value(&json!("hi"));
    /// let value2 = PEPJSONValue::from_value(&json!("hello world"));
    ///
    /// // value2 has more blocks than value1
    /// // Pad value1 to match value2's structure
    /// let target = JSONStructure::String(2);
    /// let padded = value1.pad_to(&target).unwrap();
    /// ```
    pub fn pad_to(
        &self,
        structure: &crate::data::json::structure::JSONStructure,
    ) -> Result<Self, JsonError> {
        use crate::data::json::structure::JSONStructure;

        match (self, structure) {
            (Self::Null, JSONStructure::Null) => Ok(Self::Null),
            (Self::Bool(attr), JSONStructure::Bool) => Ok(Self::Bool(*attr)),
            (Self::Number(attr), JSONStructure::Number) => Ok(Self::Number(*attr)),

            // Short string (1 block)
            (Self::String(attr), JSONStructure::String(1)) => Ok(Self::String(*attr)),

            // Short string needs to be expanded to long string
            #[cfg(feature = "long")]
            (Self::String(attr), JSONStructure::String(target_blocks)) if *target_blocks > 1 => {
                // Convert to LongAttribute with 1 block, then pad
                let long_attr = LongAttribute::from(vec![*attr]);
                let padded = long_attr.pad_to(*target_blocks).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::InvalidInput {
                        JsonError::SizeExceedsTarget {
                            current: long_attr.len(),
                            target: *target_blocks,
                        }
                    } else {
                        JsonError::StringPadding(format!("{e:?}"))
                    }
                })?;
                Ok(Self::LongString(padded))
            }

            // Long string normalization
            #[cfg(feature = "long")]
            (Self::LongString(long_attr), JSONStructure::String(target_blocks)) => {
                let padded = long_attr.pad_to(*target_blocks).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::InvalidInput {
                        JsonError::SizeExceedsTarget {
                            current: long_attr.len(),
                            target: *target_blocks,
                        }
                    } else {
                        JsonError::StringPadding(format!("{e:?}"))
                    }
                })?;
                Ok(Self::LongString(padded))
            }

            // Short pseudonym (1 block)
            (Self::Pseudonym(pseudo), JSONStructure::Pseudonym(1)) => Ok(Self::Pseudonym(*pseudo)),

            // Short pseudonym needs to be expanded to long pseudonym
            #[cfg(feature = "long")]
            (Self::Pseudonym(pseudo), JSONStructure::Pseudonym(target_blocks))
                if *target_blocks > 1 =>
            {
                // Convert to LongPseudonym with 1 block, then pad
                let long_pseudo = LongPseudonym::from(vec![*pseudo]);
                let padded = long_pseudo.pad_to(*target_blocks).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::InvalidInput {
                        JsonError::SizeExceedsTarget {
                            current: long_pseudo.len(),
                            target: *target_blocks,
                        }
                    } else {
                        JsonError::StringPadding(format!("{e:?}"))
                    }
                })?;
                Ok(Self::LongPseudonym(padded))
            }

            // Long pseudonym normalization
            #[cfg(feature = "long")]
            (Self::LongPseudonym(long_pseudo), JSONStructure::Pseudonym(target_blocks)) => {
                let padded = long_pseudo.pad_to(*target_blocks).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::InvalidInput {
                        JsonError::SizeExceedsTarget {
                            current: long_pseudo.len(),
                            target: *target_blocks,
                        }
                    } else {
                        JsonError::StringPadding(format!("{e:?}"))
                    }
                })?;
                Ok(Self::LongPseudonym(padded))
            }

            // Array padding - recursively pad each element
            (Self::Array(arr), JSONStructure::Array(target_structures)) => {
                if arr.len() != target_structures.len() {
                    return Err(JsonError::StructureMismatch {
                        expected: structure.clone(),
                        got: self.structure(),
                    });
                }

                let padded: Result<Vec<_>, _> = arr
                    .iter()
                    .zip(target_structures.iter())
                    .map(|(value, target)| value.pad_to(target))
                    .collect();

                Ok(Self::Array(padded?))
            }

            // Object padding - recursively pad each field
            (Self::Object(obj), JSONStructure::Object(target_fields)) => {
                let mut padded = HashMap::new();

                for (key, target_struct) in target_fields {
                    match obj.get(key) {
                        Some(value) => {
                            padded.insert(key.clone(), value.pad_to(target_struct)?);
                        }
                        None => {
                            return Err(JsonError::StructureMismatch {
                                expected: structure.clone(),
                                got: self.structure(),
                            });
                        }
                    }
                }

                // Check for extra fields in the object
                if obj.len() != target_fields.len() {
                    return Err(JsonError::StructureMismatch {
                        expected: structure.clone(),
                        got: self.structure(),
                    });
                }

                Ok(Self::Object(padded))
            }

            // Mismatched structure types
            _ => Err(JsonError::StructureMismatch {
                expected: structure.clone(),
                got: self.structure(),
            }),
        }
    }

    /// Get the structure/shape of this PEPJSONValue.
    ///
    /// This returns a structure descriptor that captures the type and block count
    /// of each field, without including the actual data values.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::json::data::PEPJSONValue;
    /// use libpep::data::json::structure::JSONStructure;
    /// use serde_json::json;
    ///
    /// let value = PEPJSONValue::from_value(&json!({
    ///     "name": "Alice",
    ///     "age": 30
    /// }));
    ///
    /// let structure = value.structure();
    /// // structure describes the shape: Object with String(1) and Number fields
    /// ```
    pub fn structure(&self) -> crate::data::json::structure::JSONStructure {
        use crate::data::json::structure::JSONStructure;

        match self {
            Self::Null => JSONStructure::Null,
            Self::Bool(_) => JSONStructure::Bool,
            Self::Number(_) => JSONStructure::Number,
            Self::String(_) => JSONStructure::String(1),
            #[cfg(feature = "long")]
            Self::LongString(long_attr) => JSONStructure::String(long_attr.len()),
            Self::Pseudonym(_) => JSONStructure::Pseudonym(1),
            #[cfg(feature = "long")]
            Self::LongPseudonym(long_pseudo) => JSONStructure::Pseudonym(long_pseudo.len()),
            Self::Array(arr) => JSONStructure::Array(arr.iter().map(|v| v.structure()).collect()),
            Self::Object(obj) => {
                let mut fields: Vec<_> = obj
                    .iter()
                    .map(|(k, v)| (k.clone(), v.structure()))
                    .collect();
                fields.sort_by(|a, b| a.0.cmp(&b.0));
                JSONStructure::Object(fields)
            }
        }
    }
}

impl<G: InvertibleEncoding> Encryptable for PEPJSONValue<G> {
    type Group = G;
    type EncryptedType = EncryptedPEPJSONValue<G>;
    type PublicKeyType = SessionPublicKeys<G>;

    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = GlobalPublicKeys<G>;

    fn encrypt<R: Rng + CryptoRng>(
        &self,
        keys: &Self::PublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType {
        match self {
            PEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            PEPJSONValue::Bool(attr) => {
                EncryptedPEPJSONValue::Bool(attr.encrypt(&keys.attribute, rng))
            }
            PEPJSONValue::Number(attr) => {
                EncryptedPEPJSONValue::Number(attr.encrypt(&keys.attribute, rng))
            }
            PEPJSONValue::String(attr) => {
                EncryptedPEPJSONValue::String(attr.encrypt(&keys.attribute, rng))
            }
            PEPJSONValue::LongString(long_attr) => {
                EncryptedPEPJSONValue::LongString(long_attr.encrypt(&keys.attribute, rng))
            }
            PEPJSONValue::Pseudonym(pseudo) => {
                EncryptedPEPJSONValue::Pseudonym(pseudo.encrypt(&keys.pseudonym, rng))
            }
            PEPJSONValue::LongPseudonym(long_pseudo) => {
                EncryptedPEPJSONValue::LongPseudonym(long_pseudo.encrypt(&keys.pseudonym, rng))
            }
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
    fn encrypt_global<R: Rng + CryptoRng>(
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

impl<G: InvertibleEncoding> Encrypted for EncryptedPEPJSONValue<G> {
    type Group = G;
    type UnencryptedType = PEPJSONValue<G>;
    type SecretKeyType = SessionKeys<G>;

    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = GlobalSecretKeys<G>;

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
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
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
        factor: &RerandomizeFactor<G>,
    ) -> Self {
        match self {
            EncryptedPEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                EncryptedPEPJSONValue::Bool(enc.rerandomize_known(&public_key.attribute, factor))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                EncryptedPEPJSONValue::Number(enc.rerandomize_known(&public_key.attribute, factor))
            }
            EncryptedPEPJSONValue::String(enc) => {
                EncryptedPEPJSONValue::String(enc.rerandomize_known(&public_key.attribute, factor))
            }
            EncryptedPEPJSONValue::LongString(enc) => EncryptedPEPJSONValue::LongString(
                enc.rerandomize_known(&public_key.attribute, factor),
            ),
            EncryptedPEPJSONValue::Pseudonym(enc) => EncryptedPEPJSONValue::Pseudonym(
                enc.rerandomize_known(&public_key.pseudonym, factor),
            ),
            EncryptedPEPJSONValue::LongPseudonym(enc) => EncryptedPEPJSONValue::LongPseudonym(
                enc.rerandomize_known(&public_key.pseudonym, factor),
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

impl<G: InvertibleEncoding> Transcryptable for EncryptedPEPJSONValue<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        match self {
            EncryptedPEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                EncryptedPEPJSONValue::Bool(enc.transcrypt_raw(info))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                EncryptedPEPJSONValue::Number(enc.transcrypt_raw(info))
            }
            EncryptedPEPJSONValue::String(enc) => {
                EncryptedPEPJSONValue::String(enc.transcrypt_raw(info))
            }
            EncryptedPEPJSONValue::LongString(enc) => {
                EncryptedPEPJSONValue::LongString(enc.transcrypt_raw(info))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => {
                EncryptedPEPJSONValue::Pseudonym(enc.transcrypt_raw(info))
            }
            EncryptedPEPJSONValue::LongPseudonym(enc) => {
                EncryptedPEPJSONValue::LongPseudonym(enc.transcrypt_raw(info))
            }
            EncryptedPEPJSONValue::Array(arr) => {
                EncryptedPEPJSONValue::Array(arr.iter().map(|x| x.transcrypt_raw(info)).collect())
            }
            EncryptedPEPJSONValue::Object(obj) => EncryptedPEPJSONValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.transcrypt_raw(info)))
                    .collect(),
            ),
        }
    }
}

#[cfg(feature = "batch")]
impl<G: InvertibleEncoding> crate::data::traits::HasStructure for EncryptedPEPJSONValue<G> {
    type Structure = crate::data::json::structure::JSONStructure;

    fn structure(&self) -> Self::Structure {
        self.structure()
    }
}

#[cfg(feature = "batch")]
impl<G: InvertibleEncoding> BatchEncryptable for PEPJSONValue<G> {
    fn preprocess_batch(items: &[Self]) -> Result<Vec<Self>, BatchError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }

        // Collect and unify structures
        let structures: Vec<_> = items.iter().map(|v| v.structure()).collect();
        let unified = unify_structures(&structures)?;

        // Pad each item to unified structure
        Ok(items
            .iter()
            .map(|item| item.pad_to(&unified))
            .collect::<Result<Vec<_>, _>>()?)
    }
}
