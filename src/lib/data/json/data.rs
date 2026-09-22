//! Core JSON encryption types and implementations.
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;
use thiserror::Error;

/// The [`PEPJSONValue`](generic::PEPJSONValue) over ristretto255.
pub type PEPJSONValue = generic::PEPJSONValue<Ristretto255>;
/// The [`EncryptedPEPJSONValue`](generic::EncryptedPEPJSONValue) over ristretto255.
pub type EncryptedPEPJSONValue = generic::EncryptedPEPJSONValue<Ristretto255>;

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

    #[error("invalid number encoding: {0}")]
    InvalidNumberEncoding(String),

    #[error("failed to parse string: {0}")]
    StringPadding(String),

    #[error("structure mismatch: expected {expected:?}, got {got:?}")]
    StructureMismatch {
        expected: super::structure::JSONStructure,
        got: super::structure::JSONStructure,
    },

    #[error("cannot normalize: current size {current} exceeds target size {target}")]
    SizeExceedsTarget { current: usize, target: usize },
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::{decrypt, encrypt};
    use crate::contexts::EncryptionContext;
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
        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
            let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
            let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
            let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
            let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
            let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);

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
        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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
        let encrypted1 = encrypt(&pep_value1, &keys.public_keys(), &mut rng);
        let encrypted2 = encrypt(&pep_value1, &keys.public_keys(), &mut rng);
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

    #[test]
    #[cfg(feature = "long")]
    fn normalize_short_string_to_long() {
        use super::super::structure::JSONStructure;

        // Short string (1 block)
        let short_value = PEPJSONValue::from_value(&json!("hi"));
        assert_eq!(short_value.structure(), JSONStructure::String(1));

        // Normalize to 3 blocks
        let normalized = short_value.pad_to(&JSONStructure::String(3)).unwrap();
        assert_eq!(normalized.structure(), JSONStructure::String(3));

        // Verify it's now a LongString
        match normalized {
            PEPJSONValue::LongString(ref long_attr) => {
                assert_eq!(long_attr.len(), 3);
            }
            _ => panic!("Expected LongString after normalization"),
        }
    }

    #[test]
    #[cfg(feature = "long")]
    fn normalize_long_string_adds_padding() {
        use super::super::structure::JSONStructure;

        // Long string (2 blocks)
        let long_value = PEPJSONValue::from_value(&json!("This is a longer string"));
        let initial_structure = long_value.structure();

        // Get current block count
        let current_blocks = match initial_structure {
            JSONStructure::String(n) => n,
            _ => panic!("Expected String structure"),
        };

        // Normalize to more blocks
        let target_blocks = current_blocks + 2;
        let normalized = long_value
            .pad_to(&JSONStructure::String(target_blocks))
            .unwrap();
        assert_eq!(normalized.structure(), JSONStructure::String(target_blocks));

        // Verify block count increased
        match normalized {
            PEPJSONValue::LongString(ref long_attr) => {
                assert_eq!(long_attr.len(), target_blocks);
            }
            _ => panic!("Expected LongString"),
        }
    }

    #[test]
    #[cfg(feature = "long")]
    fn normalize_strings_different_sizes_encrypt_decrypt() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Create strings of different sizes
        let short = PEPJSONValue::from_value(&json!("hi"));
        let medium = PEPJSONValue::from_value(&json!("hello world"));
        let long =
            PEPJSONValue::from_value(&json!("This is a much longer string with more content"));

        // Find the maximum block count
        let max_blocks = [&short, &medium, &long]
            .iter()
            .map(|v| match v.structure() {
                super::super::structure::JSONStructure::String(n) => n,
                _ => 0,
            })
            .max()
            .unwrap();

        // Normalize all to the same structure
        let target = super::super::structure::JSONStructure::String(max_blocks);
        let short_normalized = short.pad_to(&target).unwrap();
        let medium_normalized = medium.pad_to(&target).unwrap();
        let long_normalized = long.pad_to(&target).unwrap();

        // All should have the same structure now
        assert_eq!(short_normalized.structure(), target);
        assert_eq!(medium_normalized.structure(), target);
        assert_eq!(long_normalized.structure(), target);

        // Encrypt all values
        let short_encrypted = encrypt(&short_normalized, &keys.public_keys(), &mut rng);
        let medium_encrypted = encrypt(&medium_normalized, &keys.public_keys(), &mut rng);
        let long_encrypted = encrypt(&long_normalized, &keys.public_keys(), &mut rng);

        // All encrypted values should have the same structure
        assert_eq!(short_encrypted.structure(), medium_encrypted.structure());
        assert_eq!(medium_encrypted.structure(), long_encrypted.structure());

        // Decrypt and verify original values are preserved
        #[cfg(feature = "elgamal3")]
        {
            let short_decrypted = decrypt(&short_encrypted, &keys).unwrap();
            let medium_decrypted = decrypt(&medium_encrypted, &keys).unwrap();
            let long_decrypted = decrypt(&long_encrypted, &keys).unwrap();

            assert_eq!(json!("hi"), short_decrypted.to_value().unwrap());
            assert_eq!(json!("hello world"), medium_decrypted.to_value().unwrap());
            assert_eq!(
                json!("This is a much longer string with more content"),
                long_decrypted.to_value().unwrap()
            );
        }

        #[cfg(not(feature = "elgamal3"))]
        {
            let short_decrypted = decrypt(&short_encrypted, &keys);
            let medium_decrypted = decrypt(&medium_encrypted, &keys);
            let long_decrypted = decrypt(&long_encrypted, &keys);

            assert_eq!(json!("hi"), short_decrypted.to_value().unwrap());
            assert_eq!(json!("hello world"), medium_decrypted.to_value().unwrap());
            assert_eq!(
                json!("This is a much longer string with more content"),
                long_decrypted.to_value().unwrap()
            );
        }
    }

    #[test]
    #[cfg(feature = "long")]
    fn normalize_pseudonyms_different_sizes() {
        use super::super::structure::JSONStructure;
        use crate::pep_json;

        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Create pseudonyms of different sizes
        let short_pseudo = pep_json!(pseudonym("user123"));
        let long_pseudo = pep_json!(pseudonym("user@example.com.with.a.very.long.domain"));

        // Find the maximum block count
        let max_blocks = [&short_pseudo, &long_pseudo]
            .iter()
            .map(|v| match v.structure() {
                JSONStructure::Pseudonym(n) => n,
                _ => 0,
            })
            .max()
            .unwrap();

        // Normalize both to the same structure
        let target = JSONStructure::Pseudonym(max_blocks);
        let short_normalized = short_pseudo.pad_to(&target).unwrap();
        let long_normalized = long_pseudo.pad_to(&target).unwrap();

        // Both should have the same structure now
        assert_eq!(short_normalized.structure(), target);
        assert_eq!(long_normalized.structure(), target);

        // Encrypt and verify structures match
        let short_encrypted = encrypt(&short_normalized, &keys.public_keys(), &mut rng);
        let long_encrypted = encrypt(&long_normalized, &keys.public_keys(), &mut rng);

        assert_eq!(short_encrypted.structure(), long_encrypted.structure());

        // Decrypt and verify original values are preserved
        #[cfg(feature = "elgamal3")]
        {
            let short_decrypted = decrypt(&short_encrypted, &keys).unwrap();
            let long_decrypted = decrypt(&long_encrypted, &keys).unwrap();

            assert_eq!(json!("user123"), short_decrypted.to_value().unwrap());
            assert_eq!(
                json!("user@example.com.with.a.very.long.domain"),
                long_decrypted.to_value().unwrap()
            );
        }

        #[cfg(not(feature = "elgamal3"))]
        {
            let short_decrypted = decrypt(&short_encrypted, &keys);
            let long_decrypted = decrypt(&long_encrypted, &keys);

            assert_eq!(json!("user123"), short_decrypted.to_value().unwrap());
            assert_eq!(
                json!("user@example.com.with.a.very.long.domain"),
                long_decrypted.to_value().unwrap()
            );
        }
    }

    #[test]
    #[cfg(feature = "long")]
    fn normalize_nested_objects_different_string_sizes() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Create two objects with strings of different sizes
        let obj1 = PEPJSONValue::from_value(&json!({
            "name": "Alice",
            "email": "a@b.c"
        }));

        let obj2 = PEPJSONValue::from_value(&json!({
            "name": "Bob",
            "email": "bob.smith@example.com"
        }));

        // Get structures
        let struct1 = obj1.structure();
        let struct2 = obj2.structure();

        // Use the public unify_structures function
        let unified = super::super::structure::unify_structures(&[struct1, struct2]).unwrap();

        // Normalize both objects
        let obj1_normalized = obj1.pad_to(&unified).unwrap();
        let obj2_normalized = obj2.pad_to(&unified).unwrap();

        // Both should have the same structure now
        assert_eq!(obj1_normalized.structure(), obj2_normalized.structure());

        // Encrypt both
        let obj1_encrypted = encrypt(&obj1_normalized, &keys.public_keys(), &mut rng);
        let obj2_encrypted = encrypt(&obj2_normalized, &keys.public_keys(), &mut rng);

        // Structures should match
        assert_eq!(obj1_encrypted.structure(), obj2_encrypted.structure());

        // Decrypt and verify original values
        #[cfg(feature = "elgamal3")]
        {
            let obj1_decrypted = decrypt(&obj1_encrypted, &keys).unwrap();
            let obj2_decrypted = decrypt(&obj2_encrypted, &keys).unwrap();

            assert_eq!(
                json!({"name": "Alice", "email": "a@b.c"}),
                obj1_decrypted.to_value().unwrap()
            );
            assert_eq!(
                json!({"name": "Bob", "email": "bob.smith@example.com"}),
                obj2_decrypted.to_value().unwrap()
            );
        }

        #[cfg(not(feature = "elgamal3"))]
        {
            let obj1_decrypted = decrypt(&obj1_encrypted, &keys);
            let obj2_decrypted = decrypt(&obj2_encrypted, &keys);

            assert_eq!(
                json!({"name": "Alice", "email": "a@b.c"}),
                obj1_decrypted.to_value().unwrap()
            );
            assert_eq!(
                json!({"name": "Bob", "email": "bob.smith@example.com"}),
                obj2_decrypted.to_value().unwrap()
            );
        }
    }

    #[test]
    #[cfg(feature = "long")]
    fn normalize_errors_when_size_exceeds_target() {
        use super::super::structure::JSONStructure;

        // Create a long string (multiple blocks)
        let long_value = PEPJSONValue::from_value(&json!(
            "This is a very long string that will take multiple blocks"
        ));

        let current_blocks = match long_value.structure() {
            JSONStructure::String(n) => n,
            _ => panic!("Expected String structure"),
        };

        // Try to normalize to fewer blocks - should fail
        let result = long_value.pad_to(&JSONStructure::String(current_blocks - 1));
        assert!(result.is_err());

        match result {
            Err(JsonError::SizeExceedsTarget { current, target }) => {
                assert_eq!(current, current_blocks);
                assert_eq!(target, current_blocks - 1);
            }
            _ => panic!("Expected SizeExceedsTarget error"),
        }
    }

    #[test]
    #[cfg(feature = "long")]
    fn normalize_errors_on_structure_mismatch() {
        use super::super::structure::JSONStructure;

        // Create a string value
        let string_value = PEPJSONValue::from_value(&json!("hello"));

        // Try to normalize to a number structure - should fail
        let result = string_value.pad_to(&JSONStructure::Number);
        assert!(result.is_err());

        match result {
            Err(JsonError::StructureMismatch { expected, got }) => {
                assert_eq!(expected, JSONStructure::Number);
                assert_eq!(got, JSONStructure::String(1));
            }
            _ => panic!("Expected StructureMismatch error"),
        }
    }

    #[test]
    fn normalize_preserves_primitives() {
        use super::super::structure::JSONStructure;

        // Test that null, bool, and number normalization works
        let null_value = PEPJSONValue::from_value(&json!(null));
        let bool_value = PEPJSONValue::from_value(&json!(true));
        let number_value = PEPJSONValue::from_value(&json!(42));

        let null_normalized = null_value.pad_to(&JSONStructure::Null).unwrap();
        let bool_normalized = bool_value.pad_to(&JSONStructure::Bool).unwrap();
        let number_normalized = number_value.pad_to(&JSONStructure::Number).unwrap();

        assert_eq!(null_normalized, null_value);
        assert_eq!(bool_normalized, bool_value);
        assert_eq!(number_normalized, number_value);
    }
}
