//! The JSON value types, their conversion from and to `serde_json::Value`, and padding.
//!
//! The group must have an [`InvertibleEncoding`] for the attribute values. The encryption,
//! decryption and transcryption of these types is in [`encryption`](super::encryption).

use crate::data::elgamal::ElGamalEncryptable;
use crate::data::json::utils::{bool_to_byte, byte_to_bool, bytes_to_number, number_to_bytes};
use crate::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use crate::data::padding::Padded;
use crate::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::elgamal::arithmetic::group::InvertibleEncoding;
use crate::elgamal::arithmetic::Ristretto255;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// An error in the conversion between JSON values and their PEP encoding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonError {
    /// A boolean attribute holds a byte other than `0x00` or `0x01`.
    #[error("invalid boolean byte value: 0x{got:02x}. expected 0x00 or 0x01")]
    InvalidBoolByte {
        /// The byte found.
        got: u8,
    },
    /// A boolean attribute does not hold exactly one byte.
    #[error("expected 1 byte for bool, got {got}")]
    BoolBytesWrongLen {
        /// The number of bytes found.
        got: usize,
    },
    /// A number attribute does not hold exactly nine bytes.
    #[error("expected 9 bytes for number, got {got}")]
    NumberBytesWrongLen {
        /// The number of bytes found.
        got: usize,
    },
    /// A number attribute holds an unknown type tag or a non-finite float.
    #[error("invalid number encoding: {0}")]
    InvalidNumberEncoding(String),
    /// A value is not padded as its type requires.
    #[error(transparent)]
    Padding(#[from] crate::data::padding::PaddingError),
    /// A value does not have the structure it is padded or compared to.
    #[error("structure mismatch: expected {expected:?}, got {got:?}")]
    StructureMismatch {
        /// The structure expected.
        expected: crate::data::json::structure::JsonStructure,
        /// The structure found.
        got: crate::data::json::structure::JsonStructure,
    },
}

/// A JSON value where primitive types are stored as unencrypted PEP types.
///
/// - `Null` remains as-is
/// - `Bool` is stored as a single `Attribute` (1 byte)
/// - `Number` is stored as a single `Attribute` (9 bytes: 1 byte type tag + 8 bytes data for u64/i64/f64)
/// - `String` is stored as an `Attribute` when it fits one block, else as a `LongAttribute`
/// - `Pseudonym` is stored as a `Pseudonym` when it fits one block, else as a `LongPseudonym`
///   (can be pseudonymized/reshuffled)
/// - `Array` and `Object` contain nested `PepJsonValue`s
///
/// Call `.encrypt()` to convert this into an `EncryptedPepJsonValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PepJsonValue<G: InvertibleEncoding = Ristretto255> {
    /// JSON `null`, kept in the clear.
    Null,
    /// A boolean, as one attribute.
    Bool(Attribute<G>),
    /// A number, as one attribute.
    Number(Attribute<G>),
    /// A short string that fits in one block (at most 15 bytes).
    String(Attribute<G>),
    /// A long string of several blocks.
    LongString(LongAttribute<G>),
    /// A pseudonym of one block.
    Pseudonym(Pseudonym<G>),
    /// A pseudonym of several blocks.
    LongPseudonym(LongPseudonym<G>),
    /// An array of values.
    Array(Vec<PepJsonValue<G>>),
    /// An object of named values.
    Object(BTreeMap<String, PepJsonValue<G>>),
}

/// An encrypted JSON value where primitive types are encrypted as PEP types.
///
/// - `Null` remains unencrypted
/// - `Bool` is encrypted as a single `EncryptedAttribute` (1 byte)
/// - `Number` is encrypted as a single `EncryptedAttribute` (9 bytes: 1 byte type tag + 8 bytes data for u64/i64/f64)
/// - `String` is encrypted as an `EncryptedAttribute` or a `LongEncryptedAttribute`
/// - `Pseudonym` is encrypted as an `EncryptedPseudonym` or a `LongEncryptedPseudonym` (can be
///   pseudonymized/reshuffled)
/// - `Array` and `Object` contain nested `EncryptedPepJsonValue`s
///
/// Call `.decrypt()` to convert this back into a `PepJsonValue`, and `to_value` on that for
/// the `serde_json::Value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
#[serde(tag = "type", content = "data")]
pub enum EncryptedPepJsonValue<G: InvertibleEncoding = Ristretto255> {
    /// JSON `null`, kept in the clear.
    Null,
    /// A boolean, as one encrypted attribute.
    Bool(EncryptedAttribute<G>),
    /// A number, as one encrypted attribute.
    Number(EncryptedAttribute<G>),
    /// A short string that fits in one block (at most 15 bytes).
    String(EncryptedAttribute<G>),
    /// A long string of several blocks.
    LongString(LongEncryptedAttribute<G>),
    /// A pseudonym of one block.
    Pseudonym(EncryptedPseudonym<G>),
    /// A pseudonym of several blocks.
    LongPseudonym(LongEncryptedPseudonym<G>),
    /// An array of encrypted values.
    Array(Vec<EncryptedPepJsonValue<G>>),
    /// An object of named encrypted values.
    Object(BTreeMap<String, EncryptedPepJsonValue<G>>),
}

impl<G: InvertibleEncoding> PepJsonValue<G> {
    /// Convert this PepJsonValue back to a regular JSON Value.
    ///
    /// This extracts the underlying data from unencrypted PEP types.
    pub fn to_value(&self) -> Result<Value, JsonError> {
        match self {
            Self::Null => Ok(Value::Null),
            Self::Bool(attr) => {
                let bytes = attr.to_bytes_padded()?;
                let b = *bytes
                    .first()
                    .ok_or(JsonError::BoolBytesWrongLen { got: 0 })?;
                if bytes.len() != 1 {
                    return Err(JsonError::BoolBytesWrongLen { got: bytes.len() });
                }
                let bool_val = byte_to_bool(b)?;
                Ok(Value::Bool(bool_val))
            }
            Self::Number(attr) => {
                let bytes = attr.to_bytes_padded()?;
                let arr: [u8; 9] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| JsonError::NumberBytesWrongLen { got: bytes.len() })?;
                let num_val = bytes_to_number(&arr)?;
                Ok(Value::Number(num_val))
            }
            Self::String(attr) => {
                let string_val = attr.to_string_padded()?;
                Ok(Value::String(string_val))
            }
            Self::LongString(attr) => {
                let string_val = attr.to_string_padded()?;
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

    /// Create a PepJsonValue from a regular JSON Value.
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
                let mut out = BTreeMap::new();
                out.extend(obj.iter().map(|(k, v)| (k.clone(), Self::from_value(v))));
                Self::Object(out)
            }
        }
    }

    /// Pads this PepJsonValue to match a target structure by adding external padding blocks.
    ///
    /// This method adds external padding blocks (separate from any internal PKCS#7-style
    /// padding used inside individual ciphertext blocks) to `LongString` and
    /// `LongPseudonym` variants so that all instances have the same number of blocks
    /// when encrypted. Batch transcryption needs this: all encrypted values must
    /// have identical structure to stay unlinkable.
    ///
    /// The external padding blocks are all-zero blocks `[0x00, 0x00, ...]` that contain no user data.
    /// Decoding detects and removes them automatically, so the original values are preserved.
    ///
    /// # Parameters
    ///
    /// - `structure`: The target structure specifying the number of blocks for each field
    ///
    /// # Returns
    ///
    /// Returns a padded `PepJsonValue` with padding blocks added where necessary.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The current structure doesn't match the target structure type
    /// - The current size exceeds the target size (cannot pad by removing blocks)
    ///
    /// # Example
    ///
    /// ```
    /// use libpep::data::json::data::PepJsonValue;
    /// use libpep::data::json::structure::JsonStructure;
    /// use libpep::elgamal::arithmetic::Ristretto255;
    /// use serde_json::json;
    ///
    /// let value1 = PepJsonValue::<Ristretto255>::from_value(&json!("hi"));
    /// let value2 = PepJsonValue::<Ristretto255>::from_value(&json!("hello world"));
    ///
    /// // value2 has more blocks than value1
    /// // Pad value1 to match value2's structure
    /// let target = JsonStructure::String(2);
    /// let padded = value1.pad_to(&target).unwrap();
    /// assert_eq!(padded.structure(), target);
    /// ```
    pub fn pad_to(
        &self,
        structure: &crate::data::json::structure::JsonStructure,
    ) -> Result<Self, JsonError> {
        use crate::data::json::structure::JsonStructure;

        match (self, structure) {
            (Self::Null, JsonStructure::Null) => Ok(Self::Null),
            (Self::Bool(attr), JsonStructure::Bool) => Ok(Self::Bool(*attr)),
            (Self::Number(attr), JsonStructure::Number) => Ok(Self::Number(*attr)),

            // Short string (1 block)
            (Self::String(attr), JsonStructure::String(1)) => Ok(Self::String(*attr)),

            // Short string needs to be expanded to long string
            (Self::String(attr), JsonStructure::String(target_blocks)) if *target_blocks > 1 => {
                // Convert to LongAttribute with 1 block, then pad
                let long_attr = LongAttribute::from(vec![*attr]);
                let padded = long_attr.pad_to(*target_blocks)?;
                Ok(Self::LongString(padded))
            }

            // Long string normalization
            (Self::LongString(long_attr), JsonStructure::String(target_blocks)) => {
                let padded = long_attr.pad_to(*target_blocks)?;
                Ok(Self::LongString(padded))
            }

            // Short pseudonym (1 block)
            (Self::Pseudonym(pseudo), JsonStructure::Pseudonym(1)) => Ok(Self::Pseudonym(*pseudo)),

            // Short pseudonym needs to be expanded to long pseudonym
            (Self::Pseudonym(pseudo), JsonStructure::Pseudonym(target_blocks))
                if *target_blocks > 1 =>
            {
                // Convert to LongPseudonym with 1 block, then pad
                let long_pseudo = LongPseudonym::from(vec![*pseudo]);
                let padded = long_pseudo.pad_to(*target_blocks)?;
                Ok(Self::LongPseudonym(padded))
            }

            // Long pseudonym normalization
            (Self::LongPseudonym(long_pseudo), JsonStructure::Pseudonym(target_blocks)) => {
                let padded = long_pseudo.pad_to(*target_blocks)?;
                Ok(Self::LongPseudonym(padded))
            }

            // Array padding: recursively pad each element
            (Self::Array(arr), JsonStructure::Array(target_structures)) => {
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

            // Object padding: recursively pad each field
            (Self::Object(obj), JsonStructure::Object(target_fields)) => {
                let mut padded = BTreeMap::new();

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

    /// Get the structure/shape of this PepJsonValue.
    ///
    /// This returns a structure descriptor that captures the type and block count
    /// of each field, without including the actual data values.
    ///
    /// # Example
    ///
    /// ```
    /// use libpep::data::json::data::PepJsonValue;
    /// use libpep::data::json::structure::JsonStructure;
    /// use libpep::elgamal::arithmetic::Ristretto255;
    /// use serde_json::json;
    ///
    /// let value = PepJsonValue::<Ristretto255>::from_value(&json!({
    ///     "name": "Alice",
    ///     "age": 30
    /// }));
    ///
    /// let structure = value.structure();
    /// // The structure describes the shape: an object with a one-block string and a number.
    /// assert!(matches!(structure, JsonStructure::Object(_)));
    /// ```
    pub fn structure(&self) -> crate::data::json::structure::JsonStructure {
        use crate::data::json::structure::JsonStructure;

        match self {
            Self::Null => JsonStructure::Null,
            Self::Bool(_) => JsonStructure::Bool,
            Self::Number(_) => JsonStructure::Number,
            Self::String(_) => JsonStructure::String(1),
            Self::LongString(long_attr) => JsonStructure::String(long_attr.len()),
            Self::Pseudonym(_) => JsonStructure::Pseudonym(1),
            Self::LongPseudonym(long_pseudo) => JsonStructure::Pseudonym(long_pseudo.len()),
            Self::Array(arr) => JsonStructure::Array(arr.iter().map(|v| v.structure()).collect()),
            Self::Object(obj) => JsonStructure::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.structure()))
                    .collect(),
            ),
        }
    }
}
