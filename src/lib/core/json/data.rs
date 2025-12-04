//! Core JSON encryption types and implementations.

use crate::core::data::{encrypt_attribute, Attribute, EncryptedAttribute};
use crate::core::keys::SessionKeys;
use crate::core::long::data::{
    decrypt_long_attribute, decrypt_long_pseudonym, encrypt_long_attribute, encrypt_long_pseudonym,
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use crate::core::padding::Padded;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::utils::{bool_to_byte, byte_to_bool, bytes_to_number, number_to_bytes};

/// Error type for JSON encryption/decryption operations
pub type JsonError = String;

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
    String(LongAttribute),
    Pseudonym(LongPseudonym),
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
    String(LongEncryptedAttribute),
    Pseudonym(LongEncryptedPseudonym),
    Array(Vec<EncryptedPEPJSONValue>),
    Object(HashMap<String, EncryptedPEPJSONValue>),
}

impl PEPJSONValue {
    /// Convert this PEPJSONValue back to a regular JSON Value.
    ///
    /// This extracts the underlying data from unencrypted PEP types.
    pub fn to_value(&self) -> Result<Value, JsonError> {
        match self {
            PEPJSONValue::Null => Ok(Value::Null),
            PEPJSONValue::Bool(attr) => {
                let bytes = attr
                    .to_bytes_padded()
                    .map_err(|e| format!("Failed to get bytes from bool: {:?}", e))?;
                if bytes.len() != 1 {
                    return Err(format!("Expected 1 byte for bool, got {}", bytes.len()));
                }
                let bool_val = byte_to_bool(bytes[0])?;
                Ok(Value::Bool(bool_val))
            }
            PEPJSONValue::Number(attr) => {
                let bytes = attr
                    .to_bytes_padded()
                    .map_err(|e| format!("Failed to get bytes from number: {:?}", e))?;
                if bytes.len() != 9 {
                    return Err(format!("Expected 9 bytes for number, got {}", bytes.len()));
                }
                let mut arr = [0u8; 9];
                arr.copy_from_slice(&bytes);
                let num_val = bytes_to_number(&arr);
                Ok(Value::Number(num_val))
            }
            PEPJSONValue::String(attr) => {
                let string_val = attr
                    .to_string_padded()
                    .map_err(|e| format!("Failed to parse string: {:?}", e))?;
                Ok(Value::String(string_val))
            }
            PEPJSONValue::Pseudonym(pseudo) => {
                let string_val = pseudo.to_string_padded().unwrap_or_else(|_| {
                    // Convert to hex representation for pseudonyms that can't be represented as UTF-8
                    pseudo.to_hex()
                });
                Ok(Value::String(string_val))
            }
            PEPJSONValue::Array(arr) => {
                let mut json_arr = Vec::with_capacity(arr.len());
                for item in arr {
                    json_arr.push(item.to_value()?);
                }
                Ok(Value::Array(json_arr))
            }
            PEPJSONValue::Object(obj) => {
                let mut json_obj = serde_json::Map::with_capacity(obj.len());
                for (key, val) in obj {
                    json_obj.insert(key.clone(), val.to_value()?);
                }
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
            Value::Null => PEPJSONValue::Null,
            Value::Bool(b) => {
                let byte = bool_to_byte(*b);
                // Safety: 1 byte always fits in a 16-byte block with PKCS#7 padding
                #[allow(clippy::expect_used)]
                let attr = Attribute::from_bytes_padded(&[byte])
                    .expect("1 byte always fits in 16-byte block");
                PEPJSONValue::Bool(attr)
            }
            Value::Number(n) => {
                let bytes = number_to_bytes(n);
                // Safety: 9 bytes always fits in a 16-byte block with PKCS#7 padding
                #[allow(clippy::expect_used)]
                let attr = Attribute::from_bytes_padded(&bytes)
                    .expect("9 bytes always fits in 16-byte block");
                PEPJSONValue::Number(attr)
            }
            Value::String(s) => {
                let attr = LongAttribute::from_string_padded(s);
                PEPJSONValue::String(attr)
            }
            Value::Array(arr) => {
                let pep_arr = arr.iter().map(Self::from_value).collect();
                PEPJSONValue::Array(pep_arr)
            }
            Value::Object(obj) => {
                let pep_obj = obj
                    .iter()
                    .map(|(key, val)| (key.clone(), Self::from_value(val)))
                    .collect();
                PEPJSONValue::Object(pep_obj)
            }
        }
    }

    /// Encrypt this PEPJSONValue into an EncryptedPEPJSONValue.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        keys: &SessionKeys,
        rng: &mut R,
    ) -> EncryptedPEPJSONValue {
        match self {
            PEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            PEPJSONValue::Bool(attr) => {
                let encrypted = encrypt_attribute(attr, &keys.attribute.public, rng);
                EncryptedPEPJSONValue::Bool(encrypted)
            }
            PEPJSONValue::Number(attr) => {
                let encrypted = encrypt_attribute(attr, &keys.attribute.public, rng);
                EncryptedPEPJSONValue::Number(encrypted)
            }
            PEPJSONValue::String(long_attr) => {
                let encrypted = encrypt_long_attribute(long_attr, &keys.attribute.public, rng);
                EncryptedPEPJSONValue::String(encrypted)
            }
            PEPJSONValue::Pseudonym(long_pseudo) => {
                let encrypted = encrypt_long_pseudonym(long_pseudo, &keys.pseudonym.public, rng);
                EncryptedPEPJSONValue::Pseudonym(encrypted)
            }
            PEPJSONValue::Array(arr) => {
                let encrypted_arr = arr.iter().map(|item| item.encrypt(keys, rng)).collect();
                EncryptedPEPJSONValue::Array(encrypted_arr)
            }
            PEPJSONValue::Object(obj) => {
                let encrypted_obj = obj
                    .iter()
                    .map(|(key, val)| (key.clone(), val.encrypt(keys, rng)))
                    .collect();
                EncryptedPEPJSONValue::Object(encrypted_obj)
            }
        }
    }
}

/// Encrypt a PEPJSONValue into an EncryptedPEPJSONValue using session keys.
pub fn encrypt_json<R: RngCore + CryptoRng>(
    value: &PEPJSONValue,
    keys: &SessionKeys,
    rng: &mut R,
) -> EncryptedPEPJSONValue {
    match value {
        PEPJSONValue::Null => EncryptedPEPJSONValue::Null,
        PEPJSONValue::Bool(attr) => {
            let encrypted = encrypt_attribute(attr, &keys.attribute.public, rng);
            EncryptedPEPJSONValue::Bool(encrypted)
        }
        PEPJSONValue::Number(attr) => {
            let encrypted = encrypt_attribute(attr, &keys.attribute.public, rng);
            EncryptedPEPJSONValue::Number(encrypted)
        }
        PEPJSONValue::String(long_attr) => {
            let encrypted = encrypt_long_attribute(long_attr, &keys.attribute.public, rng);
            EncryptedPEPJSONValue::String(encrypted)
        }
        PEPJSONValue::Pseudonym(long_pseudo) => {
            let encrypted = encrypt_long_pseudonym(long_pseudo, &keys.pseudonym.public, rng);
            EncryptedPEPJSONValue::Pseudonym(encrypted)
        }
        PEPJSONValue::Array(arr) => {
            let encrypted_arr = arr
                .iter()
                .map(|item| encrypt_json(item, keys, rng))
                .collect();
            EncryptedPEPJSONValue::Array(encrypted_arr)
        }
        PEPJSONValue::Object(obj) => {
            let encrypted_obj = obj
                .iter()
                .map(|(key, val)| (key.clone(), encrypt_json(val, keys, rng)))
                .collect();
            EncryptedPEPJSONValue::Object(encrypted_obj)
        }
    }
}

/// Decrypt an EncryptedPEPJSONValue into a PEPJSONValue using session keys.
pub fn decrypt_json(
    encrypted: &EncryptedPEPJSONValue,
    keys: &SessionKeys,
) -> Result<PEPJSONValue, JsonError> {
    use crate::core::data::decrypt_attribute;

    match encrypted {
        EncryptedPEPJSONValue::Null => Ok(PEPJSONValue::Null),
        EncryptedPEPJSONValue::Bool(enc) => {
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt_attribute(enc, &keys.attribute.secret)
                .ok_or_else(|| "Failed to decrypt bool".to_string())?;
            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt_attribute(enc, &keys.attribute.secret);

            Ok(PEPJSONValue::Bool(decrypted))
        }
        EncryptedPEPJSONValue::Number(enc) => {
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt_attribute(enc, &keys.attribute.secret)
                .ok_or_else(|| "Failed to decrypt number".to_string())?;
            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt_attribute(enc, &keys.attribute.secret);

            Ok(PEPJSONValue::Number(decrypted))
        }
        EncryptedPEPJSONValue::String(enc) => {
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt_long_attribute(enc, &keys.attribute.secret)
                .ok_or_else(|| "Failed to decrypt string".to_string())?;
            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt_long_attribute(enc, &keys.attribute.secret);

            Ok(PEPJSONValue::String(decrypted))
        }
        EncryptedPEPJSONValue::Pseudonym(enc) => {
            #[cfg(feature = "elgamal3")]
            let decrypted = decrypt_long_pseudonym(enc, &keys.pseudonym.secret)
                .ok_or_else(|| "Failed to decrypt pseudonym string".to_string())?;
            #[cfg(not(feature = "elgamal3"))]
            let decrypted = decrypt_long_pseudonym(enc, &keys.pseudonym.secret);

            Ok(PEPJSONValue::Pseudonym(decrypted))
        }
        EncryptedPEPJSONValue::Array(arr) => {
            let mut decrypted_arr = Vec::with_capacity(arr.len());
            for item in arr {
                decrypted_arr.push(decrypt_json(item, keys)?);
            }
            Ok(PEPJSONValue::Array(decrypted_arr))
        }
        EncryptedPEPJSONValue::Object(obj) => {
            let mut decrypted_obj = HashMap::with_capacity(obj.len());
            for (key, val) in obj {
                decrypted_obj.insert(key.clone(), decrypt_json(val, keys)?);
            }
            Ok(PEPJSONValue::Object(decrypted_obj))
        }
    }
}

impl EncryptedPEPJSONValue {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::keys::{
        make_attribute_global_keys, make_attribute_session_keys, make_pseudonym_global_keys,
        make_pseudonym_session_keys, AttributeSessionKeys, PseudonymSessionKeys, SessionKeys,
    };
    use crate::core::transcryption::contexts::EncryptionContext;
    use crate::core::transcryption::secrets::EncryptionSecret;
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
        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        assert_eq!(value, decrypted.to_value().unwrap());
    }

    #[test]
    fn encrypt_decrypt_bool() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        for b in [true, false] {
            let value = json!(b);
            let pep_value = PEPJSONValue::from_value(&value);
            let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
            let decrypted = decrypt_json(&encrypted, &keys).unwrap();
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
            let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
            let decrypted = decrypt_json(&encrypted, &keys).unwrap();
            assert_eq!(value, decrypted.to_value().unwrap());
        }

        // Test floats
        let test_floats = [0.0, 1.5, -1.5, 37.2, 38.5, 42.42, f64::MAX, f64::MIN];
        for f in test_floats {
            let value = json!(f);
            let pep_value = PEPJSONValue::from_value(&value);
            let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
            let decrypted = decrypt_json(&encrypted, &keys).unwrap();
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
            let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
            let decrypted = decrypt_json(&encrypted, &keys).unwrap();
            assert_eq!(value, decrypted.to_value().unwrap());
        }
    }

    #[test]
    fn encrypt_decrypt_array() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!([true, 42, "hello", null]);
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

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
        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

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
        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

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
            let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
            let decrypted = decrypt_json(&encrypted, &keys).unwrap();
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
        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);

        let json_str = serde_json::to_string(&encrypted).expect("serialization should succeed");
        let deserialized: EncryptedPEPJSONValue =
            serde_json::from_str(&json_str).expect("deserialization should succeed");

        let decrypted = decrypt_json(&deserialized, &keys).unwrap();
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
        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

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
        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

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
        let encrypted1 = encrypt_json(&pep_value1, &keys, &mut rng);
        let encrypted2 = encrypt_json(&pep_value1, &keys, &mut rng);
        // Different encryptions of same plaintext should NOT be equal due to randomness
        assert_ne!(encrypted1, encrypted2);

        // Test that decrypted values are equal
        let decrypted1 = decrypt_json(&encrypted1, &keys).unwrap();
        let decrypted2 = decrypt_json(&encrypted2, &keys).unwrap();
        assert_eq!(decrypted1, decrypted2);
    }
}
