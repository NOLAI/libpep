//! JSON structure descriptors and related operations.

use super::data::generic::EncryptedPepJsonValue;
use crate::elgamal::arithmetic::group::InvertibleEncoding;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur when unifying structures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UnifyError {
    #[error("Cannot unify empty list of structures")]
    /// There are no structures to unify.
    EmptyList,

    #[error("Incompatible structure types: {0:?} and {1:?}")]
    /// Two values have different types at the same position.
    IncompatibleTypes(JsonStructure, JsonStructure),

    #[error("Arrays have different lengths: {0} and {1}")]
    /// Two arrays at the same position have different lengths.
    ArrayLengthMismatch(usize, usize),

    #[error("Objects have different fields")]
    /// Two objects at the same position have different fields.
    ObjectFieldMismatch,
}

/// Structure descriptor that describes the shape of an EncryptedPepJsonValue without its actual encrypted data.
///
/// For `String` and `Pseudonym` variants, the number of blocks is included to allow
/// comparing structures of values with different string lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum JsonStructure {
    /// JSON `null`.
    Null,
    /// A boolean.
    Bool,
    /// A number.
    Number,
    /// String attribute with number of blocks
    String(usize),
    /// Pseudonym with number of blocks
    Pseudonym(usize),
    /// An array, with the structure of every element.
    Array(Vec<JsonStructure>),
    /// An object, with the structure of every field in key order.
    Object(Vec<(String, JsonStructure)>),
}

/// Unifies multiple JSON structures by taking the maximum block count for each field.
///
/// This function is useful for batch operations where you need to normalize multiple
/// values to have the same structure. It recursively unifies nested structures,
/// taking the maximum block count for strings and pseudonyms, and ensuring that
/// arrays and objects have compatible structures.
///
/// # Parameters
///
/// - `structures`: A slice of JSON structures to unify
///
/// # Returns
///
/// Returns a unified `JsonStructure` where:
/// - For `String` and `Pseudonym`: the maximum block count across all inputs
/// - For `Array`: recursively unified element structures (all arrays must have same length)
/// - For `Object`: recursively unified field structures (all objects must have same fields)
/// - For primitives (`Null`, `Bool`, `Number`): the same type (all must match)
///
/// # Errors
///
/// Returns an error if:
/// - The input list is empty
/// - Structures have incompatible types (e.g., mixing `String` with `Number`)
/// - Arrays have different lengths
/// - Objects have different sets of fields
///
/// # Example
///
/// ```no_run
/// use libpep::data::json::structure::{JsonStructure, unify_structures};
///
/// let struct1 = JsonStructure::String(1);  // "hi"
/// let struct2 = JsonStructure::String(2);  // "hello"
/// let struct3 = JsonStructure::String(3);  // "hello world"
///
/// let unified = unify_structures(&[struct1, struct2, struct3]).unwrap();
/// assert_eq!(unified, JsonStructure::String(3));  // Maximum block count
/// ```
///
/// ## Object Example
///
/// ```no_run
/// use libpep::data::json::structure::{JsonStructure, unify_structures};
///
/// let obj1 = JsonStructure::Object(vec![
///     ("name".to_string(), JsonStructure::String(1)),
///     ("email".to_string(), JsonStructure::String(1)),
/// ]);
///
/// let obj2 = JsonStructure::Object(vec![
///     ("name".to_string(), JsonStructure::String(1)),
///     ("email".to_string(), JsonStructure::String(3)),
/// ]);
///
/// let unified = unify_structures(&[obj1, obj2]).unwrap();
/// // Result: email field has 3 blocks (max of 1 and 3)
/// ```
pub fn unify_structures(structures: &[JsonStructure]) -> Result<JsonStructure, UnifyError> {
    if structures.is_empty() {
        return Err(UnifyError::EmptyList);
    }

    if structures.len() == 1 {
        return Ok(structures[0].clone());
    }

    // Start with the first structure and unify with all others
    let mut unified = structures[0].clone();
    for structure in &structures[1..] {
        unified = unify_two_structures(&unified, structure)?;
    }

    Ok(unified)
}

/// Helper function to unify two structures.
fn unify_two_structures(
    s1: &JsonStructure,
    s2: &JsonStructure,
) -> Result<JsonStructure, UnifyError> {
    match (s1, s2) {
        // Primitives must match exactly
        (JsonStructure::Null, JsonStructure::Null) => Ok(JsonStructure::Null),
        (JsonStructure::Bool, JsonStructure::Bool) => Ok(JsonStructure::Bool),
        (JsonStructure::Number, JsonStructure::Number) => Ok(JsonStructure::Number),

        // Strings: take maximum block count
        (JsonStructure::String(n1), JsonStructure::String(n2)) => {
            Ok(JsonStructure::String(*n1.max(n2)))
        }

        // Pseudonyms: take maximum block count
        (JsonStructure::Pseudonym(n1), JsonStructure::Pseudonym(n2)) => {
            Ok(JsonStructure::Pseudonym(*n1.max(n2)))
        }

        // Arrays: must have same length, unify element-wise
        (JsonStructure::Array(arr1), JsonStructure::Array(arr2)) => {
            if arr1.len() != arr2.len() {
                return Err(UnifyError::ArrayLengthMismatch(arr1.len(), arr2.len()));
            }

            let unified_elements: Result<Vec<_>, _> = arr1
                .iter()
                .zip(arr2.iter())
                .map(|(e1, e2)| unify_two_structures(e1, e2))
                .collect();

            Ok(JsonStructure::Array(unified_elements?))
        }

        // Objects: must have same fields, unify field-wise
        (JsonStructure::Object(fields1), JsonStructure::Object(fields2)) => {
            // Convert to HashMaps for easier lookup (using owned String keys)
            let map1: HashMap<String, &JsonStructure> =
                fields1.iter().map(|(k, v)| (k.clone(), v)).collect();
            let map2: HashMap<String, &JsonStructure> =
                fields2.iter().map(|(k, v)| (k.clone(), v)).collect();

            // Check that both objects have the same set of keys
            if map1.len() != map2.len() {
                return Err(UnifyError::ObjectFieldMismatch);
            }

            let mut unified_fields = Vec::new();
            for (key, val1) in &map1 {
                match map2.get(key) {
                    Some(val2) => {
                        let unified_val = unify_two_structures(val1, val2)?;
                        unified_fields.push((key.clone(), unified_val));
                    }
                    None => return Err(UnifyError::ObjectFieldMismatch),
                }
            }

            // Sort fields to ensure consistent ordering
            unified_fields.sort_by(|a, b| a.0.cmp(&b.0));

            Ok(JsonStructure::Object(unified_fields))
        }

        // Incompatible types
        _ => Err(UnifyError::IncompatibleTypes(s1.clone(), s2.clone())),
    }
}

/// Methods for extracting structure from EncryptedPepJsonValue
impl<G: InvertibleEncoding> EncryptedPepJsonValue<G> {
    /// Get the structure/shape of this EncryptedPepJsonValue
    pub fn structure(&self) -> JsonStructure {
        match self {
            EncryptedPepJsonValue::Null => JsonStructure::Null,
            EncryptedPepJsonValue::Bool(_) => JsonStructure::Bool,
            EncryptedPepJsonValue::Number(_) => JsonStructure::Number,
            EncryptedPepJsonValue::String(_enc) => JsonStructure::String(1),
            EncryptedPepJsonValue::LongString(enc) => JsonStructure::String(enc.len()),
            EncryptedPepJsonValue::Pseudonym(_enc) => JsonStructure::Pseudonym(1),
            EncryptedPepJsonValue::LongPseudonym(enc) => JsonStructure::Pseudonym(enc.len()),
            EncryptedPepJsonValue::Array(arr) => {
                JsonStructure::Array(arr.iter().map(|item| item.structure()).collect())
            }
            EncryptedPepJsonValue::Object(obj) => {
                let mut fields: Vec<_> = obj
                    .iter()
                    .map(|(key, val)| (key.clone(), val.structure()))
                    .collect();
                fields.sort_by(|a, b| a.0.cmp(&b.0));
                JsonStructure::Object(fields)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::encrypt;
    use crate::contexts::EncryptionContext;
    use crate::data::json::data::PepJsonValue;
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
    fn structure_extraction() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!({
            "name": "test",
            "count": 42
        });
        let pep_value = PepJsonValue::from_value(&value);
        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        let structure = encrypted.structure();

        let expected = JsonStructure::Object(vec![
            ("count".to_string(), JsonStructure::Number),
            ("name".to_string(), JsonStructure::String(1)),
        ]);

        assert_eq!(structure, expected);
    }

    #[test]
    fn structure_with_block_counts() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Short string (1 block)
        let short_pep = PepJsonValue::from_value(&json!("hi"));
        let short = encrypt(&short_pep, &keys.public(), &mut rng);
        assert_eq!(short.structure(), JsonStructure::String(1));

        // Longer string (multiple blocks - each block is 16 bytes)
        let long_pep = PepJsonValue::from_value(&json!(
            "This is a longer string that will need multiple blocks"
        ));
        let long = encrypt(&long_pep, &keys.public(), &mut rng);
        if let JsonStructure::String(blocks) = long.structure() {
            assert!(blocks > 1);
        } else {
            panic!("Expected String structure");
        }

        // Primitives
        let null_pep = PepJsonValue::from_value(&json!(null));
        let null = encrypt(&null_pep, &keys.public(), &mut rng);
        assert_eq!(null.structure(), JsonStructure::Null);

        let bool_pep = PepJsonValue::from_value(&json!(true));
        let bool_val = encrypt(&bool_pep, &keys.public(), &mut rng);
        assert_eq!(bool_val.structure(), JsonStructure::Bool);

        let num_pep = PepJsonValue::from_value(&json!(42));
        let num = encrypt(&num_pep, &keys.public(), &mut rng);
        assert_eq!(num.structure(), JsonStructure::Number);
    }

    #[test]
    fn structure_with_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = pep_json!({
            "id": pseudonym("user@example.com"),
            "name": "Alice",
            "age": 30
        });
        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        let structure = encrypted.structure();

        let expected = JsonStructure::Object(vec![
            ("age".to_string(), JsonStructure::Number),
            ("id".to_string(), JsonStructure::Pseudonym(2)),
            ("name".to_string(), JsonStructure::String(1)),
        ]);

        assert_eq!(structure, expected);
    }

    #[test]
    fn structure_comparison() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Two values with the same structure
        let pep_value1 = PepJsonValue::from_value(&json!({"name": "Alice", "age": 30}));
        let value1 = encrypt(&pep_value1, &keys.public(), &mut rng);

        let pep_value2 = PepJsonValue::from_value(&json!({"name": "Bob", "age": 25}));
        let value2 = encrypt(&pep_value2, &keys.public(), &mut rng);

        // Same structure (same string lengths map to same block counts)
        assert_eq!(value1.structure(), value2.structure());

        // Different structure (different string length)
        let pep_value3 = PepJsonValue::from_value(
            &json!({"name": "A very long name that needs more blocks", "age": 25}),
        );
        let value3 = encrypt(&pep_value3, &keys.public(), &mut rng);

        assert_ne!(value1.structure(), value3.structure());
    }

    #[test]
    fn structure_nested() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PepJsonValue::from_value(&json!({
            "user": {
                "name": "Alice",
                "active": true
            },
            "scores": [88, 91, 85]
        }));
        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        let structure = encrypted.structure();

        let expected = JsonStructure::Object(vec![
            (
                "scores".to_string(),
                JsonStructure::Array(vec![
                    JsonStructure::Number,
                    JsonStructure::Number,
                    JsonStructure::Number,
                ]),
            ),
            (
                "user".to_string(),
                JsonStructure::Object(vec![
                    ("active".to_string(), JsonStructure::Bool),
                    ("name".to_string(), JsonStructure::String(1)),
                ]),
            ),
        ]);

        assert_eq!(structure, expected);
    }

    /// Example showing what JsonStructure looks like when serialized
    #[cfg(feature = "serde")]
    #[test]
    fn structure_serialization() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = pep_json!({
            "id": pseudonym("user@example.com"),
            "name": "Alice",
            "age": 30,
            "scores": [88, 91, 85]
        });
        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);

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
        let deserialized: JsonStructure = serde_json::from_str(&json_str).unwrap();
        assert_eq!(structure, deserialized);
    }

    #[test]
    fn unify_strings_different_sizes() {
        let s1 = JsonStructure::String(1);
        let s2 = JsonStructure::String(2);
        let s3 = JsonStructure::String(3);

        let unified = unify_structures(&[s1, s2, s3]).unwrap();
        assert_eq!(unified, JsonStructure::String(3));
    }

    #[test]
    fn unify_pseudonyms_different_sizes() {
        let p1 = JsonStructure::Pseudonym(1);
        let p2 = JsonStructure::Pseudonym(4);
        let p3 = JsonStructure::Pseudonym(2);

        let unified = unify_structures(&[p1, p2, p3]).unwrap();
        assert_eq!(unified, JsonStructure::Pseudonym(4));
    }

    #[test]
    fn unify_primitives() {
        let null_structures = vec![JsonStructure::Null, JsonStructure::Null];
        assert_eq!(
            unify_structures(&null_structures).unwrap(),
            JsonStructure::Null
        );

        let bool_structures = vec![JsonStructure::Bool, JsonStructure::Bool];
        assert_eq!(
            unify_structures(&bool_structures).unwrap(),
            JsonStructure::Bool
        );

        let num_structures = vec![
            JsonStructure::Number,
            JsonStructure::Number,
            JsonStructure::Number,
        ];
        assert_eq!(
            unify_structures(&num_structures).unwrap(),
            JsonStructure::Number
        );
    }

    #[test]
    fn unify_arrays() {
        let arr1 = JsonStructure::Array(vec![JsonStructure::String(1), JsonStructure::Number]);

        let arr2 = JsonStructure::Array(vec![JsonStructure::String(3), JsonStructure::Number]);

        let unified = unify_structures(&[arr1, arr2]).unwrap();
        assert_eq!(
            unified,
            JsonStructure::Array(vec![JsonStructure::String(3), JsonStructure::Number,])
        );
    }

    #[test]
    fn unify_objects() {
        let obj1 = JsonStructure::Object(vec![
            ("name".to_string(), JsonStructure::String(1)),
            ("email".to_string(), JsonStructure::String(1)),
        ]);

        let obj2 = JsonStructure::Object(vec![
            ("name".to_string(), JsonStructure::String(2)),
            ("email".to_string(), JsonStructure::String(3)),
        ]);

        let unified = unify_structures(&[obj1, obj2]).unwrap();

        // Check that the unified structure has max block counts
        let expected = JsonStructure::Object(vec![
            ("email".to_string(), JsonStructure::String(3)),
            ("name".to_string(), JsonStructure::String(2)),
        ]);

        assert_eq!(unified, expected);
    }

    #[test]
    fn unify_nested_objects() {
        let obj1 = JsonStructure::Object(vec![
            (
                "user".to_string(),
                JsonStructure::Object(vec![
                    ("name".to_string(), JsonStructure::String(1)),
                    ("id".to_string(), JsonStructure::Pseudonym(1)),
                ]),
            ),
            ("count".to_string(), JsonStructure::Number),
        ]);

        let obj2 = JsonStructure::Object(vec![
            (
                "user".to_string(),
                JsonStructure::Object(vec![
                    ("name".to_string(), JsonStructure::String(3)),
                    ("id".to_string(), JsonStructure::Pseudonym(2)),
                ]),
            ),
            ("count".to_string(), JsonStructure::Number),
        ]);

        let unified = unify_structures(&[obj1, obj2]).unwrap();

        let expected = JsonStructure::Object(vec![
            ("count".to_string(), JsonStructure::Number),
            (
                "user".to_string(),
                JsonStructure::Object(vec![
                    ("id".to_string(), JsonStructure::Pseudonym(2)),
                    ("name".to_string(), JsonStructure::String(3)),
                ]),
            ),
        ]);

        assert_eq!(unified, expected);
    }

    #[test]
    fn unify_single_structure() {
        let s = JsonStructure::String(5);
        let unified = unify_structures(std::slice::from_ref(&s)).unwrap();
        assert_eq!(unified, s);
    }

    #[test]
    fn unify_empty_list_fails() {
        let result = unify_structures(&[]);
        assert!(matches!(result, Err(UnifyError::EmptyList)));
    }

    #[test]
    fn unify_incompatible_types_fails() {
        let s1 = JsonStructure::String(1);
        let s2 = JsonStructure::Number;

        let result = unify_structures(&[s1, s2]);
        assert!(matches!(result, Err(UnifyError::IncompatibleTypes(_, _))));
    }

    #[test]
    fn unify_arrays_different_lengths_fails() {
        let arr1 = JsonStructure::Array(vec![JsonStructure::Number, JsonStructure::Number]);
        let arr2 = JsonStructure::Array(vec![JsonStructure::Number]);

        let result = unify_structures(&[arr1, arr2]);
        assert!(matches!(result, Err(UnifyError::ArrayLengthMismatch(2, 1))));
    }

    #[test]
    fn unify_objects_different_fields_fails() {
        let obj1 = JsonStructure::Object(vec![("name".to_string(), JsonStructure::String(1))]);

        let obj2 = JsonStructure::Object(vec![("email".to_string(), JsonStructure::String(1))]);

        let result = unify_structures(&[obj1, obj2]);
        assert!(matches!(result, Err(UnifyError::ObjectFieldMismatch)));
    }

    #[test]
    fn unify_real_world_example() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Create three different user objects with varying string lengths
        let user1 = PepJsonValue::from_value(&json!({
            "name": "Alice",
            "email": "a@b.c"
        }));

        let user2 = PepJsonValue::from_value(&json!({
            "name": "Bob",
            "email": "bob@example.com"
        }));

        let user3 = PepJsonValue::from_value(&json!({
            "name": "Charlie Johnson",
            "email": "charlie.johnson@verylongdomain.example.com"
        }));

        // Encrypt them
        let enc1 = encrypt(&user1, &keys.public(), &mut rng);
        let enc2 = encrypt(&user2, &keys.public(), &mut rng);
        let enc3 = encrypt(&user3, &keys.public(), &mut rng);

        // Get their structures
        let struct1 = enc1.structure();
        let struct2 = enc2.structure();
        let struct3 = enc3.structure();

        // Unify the structures
        let unified = unify_structures(&[struct1, struct2, struct3]).unwrap();

        // The unified structure should have the maximum block count for each field
        match unified {
            JsonStructure::Object(fields) => {
                // Find email and name fields
                let email_struct = fields.iter().find(|(k, _)| k == "email").unwrap().1.clone();
                let name_struct = fields.iter().find(|(k, _)| k == "name").unwrap().1.clone();

                // Email should have the max blocks from all three users
                if let JsonStructure::String(email_blocks) = email_struct {
                    // user3's email is the longest
                    assert!(email_blocks >= 2);
                } else {
                    panic!("Expected String structure for email");
                }

                // Name should have the max blocks from all three users
                if let JsonStructure::String(name_blocks) = name_struct {
                    // user3's name is the longest
                    assert!(name_blocks >= 1);
                } else {
                    panic!("Expected String structure for name");
                }
            }
            _ => panic!("Expected Object structure"),
        }
    }
}
