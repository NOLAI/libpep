//! JSON structure descriptors and related operations.

use super::data::EncryptedPEPJSONValue;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Structure descriptor that describes the shape of an EncryptedPEPJSONValue without its actual encrypted data.
///
/// For `String` and `Pseudonym` variants, the number of blocks is included to allow
/// comparing structures of values with different string lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum JSONStructure {
    Null,
    Bool,
    Number,
    /// String attribute with number of blocks
    String(usize),
    /// Pseudonym with number of blocks
    Pseudonym(usize),
    Array(Vec<JSONStructure>),
    Object(Vec<(String, JSONStructure)>),
}

/// Methods for extracting structure from EncryptedPEPJSONValue
impl EncryptedPEPJSONValue {
    /// Get the structure/shape of this EncryptedPEPJSONValue
    pub fn structure(&self) -> JSONStructure {
        match self {
            EncryptedPEPJSONValue::Null => JSONStructure::Null,
            EncryptedPEPJSONValue::Bool(_) => JSONStructure::Bool,
            EncryptedPEPJSONValue::Number(_) => JSONStructure::Number,
            EncryptedPEPJSONValue::String(enc) => JSONStructure::String(enc.0.len()),
            EncryptedPEPJSONValue::Pseudonym(enc) => JSONStructure::Pseudonym(enc.0.len()),
            EncryptedPEPJSONValue::Array(arr) => {
                JSONStructure::Array(arr.iter().map(|item| item.structure()).collect())
            }
            EncryptedPEPJSONValue::Object(obj) => {
                let mut fields: Vec<_> = obj
                    .iter()
                    .map(|(key, val)| (key.clone(), val.structure()))
                    .collect();
                // Sort for consistent comparison
                fields.sort_by(|a, b| a.0.cmp(&b.0));
                JSONStructure::Object(fields)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::json::data::PEPJSONValue;
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
    fn structure_extraction() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!({
            "name": "test",
            "count": 42
        });
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = pep_value.encrypt(&keys, &mut rng);
        let structure = encrypted.structure();

        let expected = JSONStructure::Object(vec![
            ("count".to_string(), JSONStructure::Number),
            ("name".to_string(), JSONStructure::String(1)),
        ]);

        assert_eq!(structure, expected);
    }

    #[test]
    fn structure_with_block_counts() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Short string (1 block)
        let short_pep = PEPJSONValue::from_value(&json!("hi"));
        let short = short_pep.encrypt(&keys, &mut rng);
        assert_eq!(short.structure(), JSONStructure::String(1));

        // Longer string (multiple blocks - each block is 16 bytes)
        let long_pep = PEPJSONValue::from_value(&json!(
            "This is a longer string that will need multiple blocks"
        ));
        let long = long_pep.encrypt(&keys, &mut rng);
        if let JSONStructure::String(blocks) = long.structure() {
            assert!(blocks > 1);
        } else {
            panic!("Expected String structure");
        }

        // Primitives
        let null_pep = PEPJSONValue::from_value(&json!(null));
        let null = null_pep.encrypt(&keys, &mut rng);
        assert_eq!(null.structure(), JSONStructure::Null);

        let bool_pep = PEPJSONValue::from_value(&json!(true));
        let bool_val = bool_pep.encrypt(&keys, &mut rng);
        assert_eq!(bool_val.structure(), JSONStructure::Bool);

        let num_pep = PEPJSONValue::from_value(&json!(42));
        let num = num_pep.encrypt(&keys, &mut rng);
        assert_eq!(num.structure(), JSONStructure::Number);
    }

    #[test]
    fn structure_with_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        use crate::pep_json;

        let pep_value = pep_json!({
            "id": pseudonym("user@example.com"),
            "name": "Alice",
            "age": 30
        });
        let encrypted = pep_value.encrypt(&keys, &mut rng);
        let structure = encrypted.structure();

        let expected = JSONStructure::Object(vec![
            ("age".to_string(), JSONStructure::Number),
            ("id".to_string(), JSONStructure::Pseudonym(2)),
            ("name".to_string(), JSONStructure::String(1)),
        ]);

        assert_eq!(structure, expected);
    }

    #[test]
    fn structure_comparison() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Two values with the same structure
        let pep_value1 = PEPJSONValue::from_value(&json!({"name": "Alice", "age": 30}));
        let value1 = pep_value1.encrypt(&keys, &mut rng);

        let pep_value2 = PEPJSONValue::from_value(&json!({"name": "Bob", "age": 25}));
        let value2 = pep_value2.encrypt(&keys, &mut rng);

        // Same structure (same string lengths map to same block counts)
        assert_eq!(value1.structure(), value2.structure());

        // Different structure (different string length)
        let pep_value3 = PEPJSONValue::from_value(
            &json!({"name": "A very long name that needs more blocks", "age": 25}),
        );
        let value3 = pep_value3.encrypt(&keys, &mut rng);

        assert_ne!(value1.structure(), value3.structure());
    }

    #[test]
    fn structure_nested() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PEPJSONValue::from_value(&json!({
            "user": {
                "name": "Alice",
                "active": true
            },
            "scores": [88, 91, 85]
        }));
        let encrypted = pep_value.encrypt(&keys, &mut rng);
        let structure = encrypted.structure();

        let expected = JSONStructure::Object(vec![
            (
                "scores".to_string(),
                JSONStructure::Array(vec![
                    JSONStructure::Number,
                    JSONStructure::Number,
                    JSONStructure::Number,
                ]),
            ),
            (
                "user".to_string(),
                JSONStructure::Object(vec![
                    ("active".to_string(), JSONStructure::Bool),
                    ("name".to_string(), JSONStructure::String(1)),
                ]),
            ),
        ]);

        assert_eq!(structure, expected);
    }

    /// Example showing what JSONStructure looks like when serialized
    #[cfg(feature = "serde")]
    #[test]
    fn structure_serialization() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        use crate::pep_json;

        let pep_value = pep_json!({
            "id": pseudonym("user@example.com"),
            "name": "Alice",
            "age": 30,
            "scores": [88, 91, 85]
        });
        let encrypted = pep_value.encrypt(&keys, &mut rng);

        let structure = encrypted.structure();

        // Serialize to JSON to show what the structure looks like
        let json_str = serde_json::to_string_pretty(&structure).unwrap();

        // Example output:
        // {
        //   "Object": [
        //     ["age", "Number"],
        //     ["id", { "Pseudonym": 2 }],
        //     ["name", { "String": 1 }],
        //     ["scores", { "Array": ["Number", "Number", "Number"] }]
        //   ]
        // }

        // Verify it can be deserialized back
        let deserialized: JSONStructure = serde_json::from_str(&json_str).unwrap();
        assert_eq!(structure, deserialized);
    }
}
