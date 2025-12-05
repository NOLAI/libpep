//! Builder pattern for constructing PEPJSONValue objects.

use serde_json::Value;
use std::collections::HashMap;

use super::data::PEPJSONValue;
use crate::core::long::data::LongPseudonym;

/// Builder for constructing PEPJSONValue objects with mixed attribute and pseudonym fields.
///
/// # Example
///
/// ```ignore
/// let pep_value = PEPJSONBuilder::new()
///     .pseudonym("id", "user1@example.com")
///     .attribute("age", json!(16))
///     .attribute("verified", json!(true))
///     .attribute("scores", json!([88, 91, 85]))
///     .build();
///
/// // Then encrypt it
/// let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
/// ```
pub struct PEPJSONBuilder {
    fields: HashMap<String, PEPJSONValue>,
}

impl PEPJSONBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Create a builder from a JSON object, marking specified fields as pseudonyms.
    ///
    /// Takes a JSON value (must be an object) and a slice of field names that should
    /// be treated as pseudonyms. All other string fields are treated as regular attributes.
    ///
    /// # Arguments
    ///
    /// * `json` - A JSON value (must be an object)
    /// * `pseudonyms` - A slice of field names that should be treated as pseudonyms
    ///
    /// # Returns
    ///
    /// A `PEPJSONBuilder` with fields populated from the JSON object.
    /// Returns `None` if the JSON value is not an object or if a pseudonym field is not a string.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use serde_json::json;
    ///
    /// let data = json!({
    ///     "id": "user@example.com",
    ///     "name": "Alice",
    ///     "age": 30
    /// });
    ///
    /// let builder = PEPJSONBuilder::from_json(&data, &["id"]).unwrap();
    /// let pep_value = builder.build();
    /// ```
    pub fn from_json(json: &Value, pseudonyms: &[&str]) -> Option<Self> {
        let obj = json.as_object()?;
        let mut builder = Self::new();

        for (key, value) in obj {
            if pseudonyms.contains(&key.as_str()) {
                // This field should be a pseudonym
                let string_value = value.as_str()?;
                builder = builder.pseudonym(key, string_value);
            } else {
                // Regular attribute
                builder = builder.attribute(key, value.clone());
            }
        }

        Some(builder)
    }

    /// Add a field as a regular attribute (from a JSON value).
    pub fn attribute(mut self, key: &str, value: Value) -> Self {
        let pep_value = PEPJSONValue::from_value(&value);
        self.fields.insert(key.to_string(), pep_value);
        self
    }

    /// Add a string field as a pseudonym.
    pub fn pseudonym(mut self, key: &str, value: &str) -> Self {
        let pseudo = LongPseudonym::from_string_padded(value);
        self.fields
            .insert(key.to_string(), PEPJSONValue::Pseudonym(pseudo));
        self
    }

    /// Build the final PEPJSONValue object.
    pub fn build(self) -> PEPJSONValue {
        PEPJSONValue::Object(self.fields)
    }
}

impl Default for PEPJSONBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::json::data::{decrypt_json, encrypt_json};
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
    fn builder_with_pseudonym_id() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PEPJSONBuilder::new()
            .pseudonym("id", "user1@example.com")
            .attribute("age", json!(16))
            .attribute("verified", json!(true))
            .attribute("scores", json!([88, 91, 85]))
            .build();

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
    fn builder_empty_object() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PEPJSONBuilder::new().build();

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        assert_eq!(json!({}), decrypted.to_value().unwrap());
    }

    #[test]
    fn builder_only_attributes() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PEPJSONBuilder::new()
            .attribute("name", json!("Alice"))
            .attribute("age", json!(30))
            .build();

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        let expected = json!({
            "name": "Alice",
            "age": 30
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    #[test]
    fn builder_only_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PEPJSONBuilder::new()
            .pseudonym("id1", "user1@example.com")
            .pseudonym("id2", "user2@example.com")
            .build();

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        let expected = json!({
            "id1": "user1@example.com",
            "id2": "user2@example.com"
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    #[test]
    fn from_json_with_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let data = json!({
            "id": "user@example.com",
            "name": "Alice",
            "age": 30,
            "verified": true
        });

        let pep_value = PEPJSONBuilder::from_json(&data, &["id"]).unwrap().build();

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        assert_eq!(data, decrypted.to_value().unwrap());
    }

    #[test]
    fn from_json_multiple_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let data = json!({
            "user_id": "user@example.com",
            "email": "user@example.com",
            "name": "Alice",
            "age": 30
        });

        let pep_value = PEPJSONBuilder::from_json(&data, &["user_id", "email"])
            .unwrap()
            .build();

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        assert_eq!(data, decrypted.to_value().unwrap());
    }

    #[test]
    fn from_json_no_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let data = json!({
            "name": "Alice",
            "age": 30,
            "scores": [88, 91, 85]
        });

        let pep_value = PEPJSONBuilder::from_json(&data, &[]).unwrap().build();

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        assert_eq!(data, decrypted.to_value().unwrap());
    }

    #[test]
    fn from_json_empty_object() {
        let data = json!({});

        let pep_value = PEPJSONBuilder::from_json(&data, &[]).unwrap().build();

        // Just verify it can be built
        assert!(matches!(pep_value, PEPJSONValue::Object(_)));
    }

    #[test]
    fn from_json_non_object_returns_none() {
        let data = json!([1, 2, 3]);
        assert!(PEPJSONBuilder::from_json(&data, &[]).is_none());

        let data = json!("string");
        assert!(PEPJSONBuilder::from_json(&data, &[]).is_none());

        let data = json!(42);
        assert!(PEPJSONBuilder::from_json(&data, &[]).is_none());
    }

    #[test]
    fn from_json_pseudonym_not_string_returns_none() {
        let data = json!({
            "id": 123,
            "name": "Alice"
        });

        // "id" should be a pseudonym but it's not a string
        assert!(PEPJSONBuilder::from_json(&data, &["id"]).is_none());
    }
}
