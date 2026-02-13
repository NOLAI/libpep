//! JSON structure descriptors and related operations.

use super::data::EncryptedPEPJSONValue;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur when unifying structures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UnifyError {
    #[error("Cannot unify empty list of structures")]
    EmptyList,

    #[error("Incompatible structure types: {0:?} and {1:?}")]
    IncompatibleTypes(JSONStructure, JSONStructure),

    #[error("Arrays have different lengths: {0} and {1}")]
    ArrayLengthMismatch(usize, usize),

    #[error("Objects have different fields")]
    ObjectFieldMismatch,
}

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
/// Returns a unified `JSONStructure` where:
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
/// use libpep::data::json::structure::{JSONStructure, unify_structures};
///
/// let struct1 = JSONStructure::String(1);  // "hi"
/// let struct2 = JSONStructure::String(2);  // "hello"
/// let struct3 = JSONStructure::String(3);  // "hello world"
///
/// let unified = unify_structures(&[struct1, struct2, struct3]).unwrap();
/// assert_eq!(unified, JSONStructure::String(3));  // Maximum block count
/// ```
///
/// ## Object Example
///
/// ```no_run
/// use libpep::data::json::structure::{JSONStructure, unify_structures};
///
/// let obj1 = JSONStructure::Object(vec![
///     ("name".to_string(), JSONStructure::String(1)),
///     ("email".to_string(), JSONStructure::String(1)),
/// ]);
///
/// let obj2 = JSONStructure::Object(vec![
///     ("name".to_string(), JSONStructure::String(1)),
///     ("email".to_string(), JSONStructure::String(3)),
/// ]);
///
/// let unified = unify_structures(&[obj1, obj2]).unwrap();
/// // Result: email field has 3 blocks (max of 1 and 3)
/// ```
pub fn unify_structures(structures: &[JSONStructure]) -> Result<JSONStructure, UnifyError> {
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
    s1: &JSONStructure,
    s2: &JSONStructure,
) -> Result<JSONStructure, UnifyError> {
    match (s1, s2) {
        // Primitives must match exactly
        (JSONStructure::Null, JSONStructure::Null) => Ok(JSONStructure::Null),
        (JSONStructure::Bool, JSONStructure::Bool) => Ok(JSONStructure::Bool),
        (JSONStructure::Number, JSONStructure::Number) => Ok(JSONStructure::Number),

        // Strings: take maximum block count
        (JSONStructure::String(n1), JSONStructure::String(n2)) => {
            Ok(JSONStructure::String(*n1.max(n2)))
        }

        // Pseudonyms: take maximum block count
        (JSONStructure::Pseudonym(n1), JSONStructure::Pseudonym(n2)) => {
            Ok(JSONStructure::Pseudonym(*n1.max(n2)))
        }

        // Arrays: must have same length, unify element-wise
        (JSONStructure::Array(arr1), JSONStructure::Array(arr2)) => {
            if arr1.len() != arr2.len() {
                return Err(UnifyError::ArrayLengthMismatch(arr1.len(), arr2.len()));
            }

            let unified_elements: Result<Vec<_>, _> = arr1
                .iter()
                .zip(arr2.iter())
                .map(|(e1, e2)| unify_two_structures(e1, e2))
                .collect();

            Ok(JSONStructure::Array(unified_elements?))
        }

        // Objects: must have same fields, unify field-wise
        (JSONStructure::Object(fields1), JSONStructure::Object(fields2)) => {
            // Convert to HashMaps for easier lookup (using owned String keys)
            let map1: HashMap<String, &JSONStructure> =
                fields1.iter().map(|(k, v)| (k.clone(), v)).collect();
            let map2: HashMap<String, &JSONStructure> =
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

            Ok(JSONStructure::Object(unified_fields))
        }

        // Incompatible types
        _ => Err(UnifyError::IncompatibleTypes(s1.clone(), s2.clone())),
    }
}

/// Methods for extracting structure from EncryptedPEPJSONValue
impl EncryptedPEPJSONValue {
    /// Get the structure/shape of this EncryptedPEPJSONValue
    pub fn structure(&self) -> JSONStructure {
        match self {
            EncryptedPEPJSONValue::Null => JSONStructure::Null,
            EncryptedPEPJSONValue::Bool(_) => JSONStructure::Bool,
            EncryptedPEPJSONValue::Number(_) => JSONStructure::Number,
            EncryptedPEPJSONValue::String(_enc) => JSONStructure::String(1),
            EncryptedPEPJSONValue::LongString(enc) => JSONStructure::String(enc.len()),
            EncryptedPEPJSONValue::Pseudonym(_enc) => JSONStructure::Pseudonym(1),
            EncryptedPEPJSONValue::LongPseudonym(enc) => JSONStructure::Pseudonym(enc.len()),
            EncryptedPEPJSONValue::Array(arr) => {
                JSONStructure::Array(arr.iter().map(|item| item.structure()).collect())
            }
            EncryptedPEPJSONValue::Object(obj) => {
                let mut fields: Vec<_> = obj
                    .iter()
                    .map(|(key, val)| (key.clone(), val.structure()))
                    .collect();
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
    use crate::client::encrypt;
    use crate::data::json::data::PEPJSONValue;
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
    fn structure_extraction() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let value = json!({
            "name": "test",
            "count": 42
        });
        let pep_value = PEPJSONValue::from_value(&value);
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
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
        let short = encrypt(&short_pep, &keys, &mut rng);
        assert_eq!(short.structure(), JSONStructure::String(1));

        // Longer string (multiple blocks - each block is 16 bytes)
        let long_pep = PEPJSONValue::from_value(&json!(
            "This is a longer string that will need multiple blocks"
        ));
        let long = encrypt(&long_pep, &keys, &mut rng);
        if let JSONStructure::String(blocks) = long.structure() {
            assert!(blocks > 1);
        } else {
            panic!("Expected String structure");
        }

        // Primitives
        let null_pep = PEPJSONValue::from_value(&json!(null));
        let null = encrypt(&null_pep, &keys, &mut rng);
        assert_eq!(null.structure(), JSONStructure::Null);

        let bool_pep = PEPJSONValue::from_value(&json!(true));
        let bool_val = encrypt(&bool_pep, &keys, &mut rng);
        assert_eq!(bool_val.structure(), JSONStructure::Bool);

        let num_pep = PEPJSONValue::from_value(&json!(42));
        let num = encrypt(&num_pep, &keys, &mut rng);
        assert_eq!(num.structure(), JSONStructure::Number);
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
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
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
        let value1 = encrypt(&pep_value1, &keys, &mut rng);

        let pep_value2 = PEPJSONValue::from_value(&json!({"name": "Bob", "age": 25}));
        let value2 = encrypt(&pep_value2, &keys, &mut rng);

        // Same structure (same string lengths map to same block counts)
        assert_eq!(value1.structure(), value2.structure());

        // Different structure (different string length)
        let pep_value3 = PEPJSONValue::from_value(
            &json!({"name": "A very long name that needs more blocks", "age": 25}),
        );
        let value3 = encrypt(&pep_value3, &keys, &mut rng);

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
        let encrypted = encrypt(&pep_value, &keys, &mut rng);
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

        let pep_value = pep_json!({
            "id": pseudonym("user@example.com"),
            "name": "Alice",
            "age": 30,
            "scores": [88, 91, 85]
        });
        let encrypted = encrypt(&pep_value, &keys, &mut rng);

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

    #[test]
    fn unify_strings_different_sizes() {
        let s1 = JSONStructure::String(1);
        let s2 = JSONStructure::String(2);
        let s3 = JSONStructure::String(3);

        let unified = unify_structures(&[s1, s2, s3]).unwrap();
        assert_eq!(unified, JSONStructure::String(3));
    }

    #[test]
    fn unify_pseudonyms_different_sizes() {
        let p1 = JSONStructure::Pseudonym(1);
        let p2 = JSONStructure::Pseudonym(4);
        let p3 = JSONStructure::Pseudonym(2);

        let unified = unify_structures(&[p1, p2, p3]).unwrap();
        assert_eq!(unified, JSONStructure::Pseudonym(4));
    }

    #[test]
    fn unify_primitives() {
        let null_structures = vec![JSONStructure::Null, JSONStructure::Null];
        assert_eq!(
            unify_structures(&null_structures).unwrap(),
            JSONStructure::Null
        );

        let bool_structures = vec![JSONStructure::Bool, JSONStructure::Bool];
        assert_eq!(
            unify_structures(&bool_structures).unwrap(),
            JSONStructure::Bool
        );

        let num_structures = vec![
            JSONStructure::Number,
            JSONStructure::Number,
            JSONStructure::Number,
        ];
        assert_eq!(
            unify_structures(&num_structures).unwrap(),
            JSONStructure::Number
        );
    }

    #[test]
    fn unify_arrays() {
        let arr1 = JSONStructure::Array(vec![JSONStructure::String(1), JSONStructure::Number]);

        let arr2 = JSONStructure::Array(vec![JSONStructure::String(3), JSONStructure::Number]);

        let unified = unify_structures(&[arr1, arr2]).unwrap();
        assert_eq!(
            unified,
            JSONStructure::Array(vec![JSONStructure::String(3), JSONStructure::Number,])
        );
    }

    #[test]
    fn unify_objects() {
        let obj1 = JSONStructure::Object(vec![
            ("name".to_string(), JSONStructure::String(1)),
            ("email".to_string(), JSONStructure::String(1)),
        ]);

        let obj2 = JSONStructure::Object(vec![
            ("name".to_string(), JSONStructure::String(2)),
            ("email".to_string(), JSONStructure::String(3)),
        ]);

        let unified = unify_structures(&[obj1, obj2]).unwrap();

        // Check that the unified structure has max block counts
        let expected = JSONStructure::Object(vec![
            ("email".to_string(), JSONStructure::String(3)),
            ("name".to_string(), JSONStructure::String(2)),
        ]);

        assert_eq!(unified, expected);
    }

    #[test]
    fn unify_nested_objects() {
        let obj1 = JSONStructure::Object(vec![
            (
                "user".to_string(),
                JSONStructure::Object(vec![
                    ("name".to_string(), JSONStructure::String(1)),
                    ("id".to_string(), JSONStructure::Pseudonym(1)),
                ]),
            ),
            ("count".to_string(), JSONStructure::Number),
        ]);

        let obj2 = JSONStructure::Object(vec![
            (
                "user".to_string(),
                JSONStructure::Object(vec![
                    ("name".to_string(), JSONStructure::String(3)),
                    ("id".to_string(), JSONStructure::Pseudonym(2)),
                ]),
            ),
            ("count".to_string(), JSONStructure::Number),
        ]);

        let unified = unify_structures(&[obj1, obj2]).unwrap();

        let expected = JSONStructure::Object(vec![
            ("count".to_string(), JSONStructure::Number),
            (
                "user".to_string(),
                JSONStructure::Object(vec![
                    ("id".to_string(), JSONStructure::Pseudonym(2)),
                    ("name".to_string(), JSONStructure::String(3)),
                ]),
            ),
        ]);

        assert_eq!(unified, expected);
    }

    #[test]
    fn unify_single_structure() {
        let s = JSONStructure::String(5);
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
        let s1 = JSONStructure::String(1);
        let s2 = JSONStructure::Number;

        let result = unify_structures(&[s1, s2]);
        assert!(matches!(result, Err(UnifyError::IncompatibleTypes(_, _))));
    }

    #[test]
    fn unify_arrays_different_lengths_fails() {
        let arr1 = JSONStructure::Array(vec![JSONStructure::Number, JSONStructure::Number]);
        let arr2 = JSONStructure::Array(vec![JSONStructure::Number]);

        let result = unify_structures(&[arr1, arr2]);
        assert!(matches!(result, Err(UnifyError::ArrayLengthMismatch(2, 1))));
    }

    #[test]
    fn unify_objects_different_fields_fails() {
        let obj1 = JSONStructure::Object(vec![("name".to_string(), JSONStructure::String(1))]);

        let obj2 = JSONStructure::Object(vec![("email".to_string(), JSONStructure::String(1))]);

        let result = unify_structures(&[obj1, obj2]);
        assert!(matches!(result, Err(UnifyError::ObjectFieldMismatch)));
    }

    #[test]
    fn unify_real_world_example() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        // Create three different user objects with varying string lengths
        let user1 = PEPJSONValue::from_value(&json!({
            "name": "Alice",
            "email": "a@b.c"
        }));

        let user2 = PEPJSONValue::from_value(&json!({
            "name": "Bob",
            "email": "bob@example.com"
        }));

        let user3 = PEPJSONValue::from_value(&json!({
            "name": "Charlie Johnson",
            "email": "charlie.johnson@verylongdomain.example.com"
        }));

        // Encrypt them
        let enc1 = encrypt(&user1, &keys, &mut rng);
        let enc2 = encrypt(&user2, &keys, &mut rng);
        let enc3 = encrypt(&user3, &keys, &mut rng);

        // Get their structures
        let struct1 = enc1.structure();
        let struct2 = enc2.structure();
        let struct3 = enc3.structure();

        // Unify the structures
        let unified = unify_structures(&[struct1, struct2, struct3]).unwrap();

        // The unified structure should have the maximum block count for each field
        match unified {
            JSONStructure::Object(fields) => {
                // Find email and name fields
                let email_struct = fields.iter().find(|(k, _)| k == "email").unwrap().1.clone();
                let name_struct = fields.iter().find(|(k, _)| k == "name").unwrap().1.clone();

                // Email should have the max blocks from all three users
                if let JSONStructure::String(email_blocks) = email_struct {
                    // user3's email is the longest
                    assert!(email_blocks >= 2);
                } else {
                    panic!("Expected String structure for email");
                }

                // Name should have the max blocks from all three users
                if let JSONStructure::String(name_blocks) = name_struct {
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
