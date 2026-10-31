//! Builder pattern for constructing PepJsonValue objects.
//!
//! The builder is generic over the [`Group`](crate::elgamal::arithmetic::Group).

use serde_json::Value;
use std::collections::BTreeMap;

use crate::data::json::data::PepJsonValue;
use crate::data::long::LongPseudonym;
use crate::elgamal::arithmetic::group::InvertibleEncoding;

/// Builder for constructing PepJsonValue objects with mixed attribute and pseudonym fields.
///
/// # Example
///
/// ```
/// use libpep::client::{decrypt, encrypt};
/// use libpep::contexts::EncryptionContext;
/// use libpep::data::json::builder::PepJsonBuilder;
/// use libpep::elgamal::arithmetic::Ristretto255;
/// use libpep::factors::EncryptionSecret;
/// use libpep::keys::{make_global_keys, make_session_keys};
/// use libpep::elgamal::arithmetic::Ristretto255Sha512;
/// use serde_json::json;
///
/// let rng = &mut rand::rng();
/// let (_global_public, global_secret) = make_global_keys::<Ristretto255, _>(rng);
/// let secret = EncryptionSecret::from(b"encryption secret".to_vec());
/// let keys = make_session_keys::<Ristretto255Sha512>(&global_secret, &EncryptionContext::from("session"), &secret);
///
/// let pep_value = PepJsonBuilder::<Ristretto255>::new()
///     .pseudonym("id", "user1@example.com")
///     .attribute("age", json!(16))
///     .attribute("verified", json!(true))
///     .attribute("scores", json!([88, 91, 85]))
///     .build();
///
/// // Then encrypt it
/// let encrypted = encrypt(&pep_value, &keys.public(), rng);
/// # #[cfg(not(feature = "elgamal3"))]
/// # let decrypted = decrypt(&encrypted, &keys);
/// # #[cfg(feature = "elgamal3")]
/// # let decrypted = decrypt(&encrypted, &keys).unwrap();
/// # assert_eq!(decrypted, pep_value);
/// ```
pub struct PepJsonBuilder<G: InvertibleEncoding> {
    fields: BTreeMap<String, PepJsonValue<G>>,
}

impl<G: InvertibleEncoding> PepJsonBuilder<G> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
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
    /// A `PepJsonBuilder` with fields populated from the JSON object.
    /// Returns `None` if the JSON value is not an object or if a pseudonym field is not a string.
    ///
    /// # Example
    ///
    /// ```
    /// use libpep::data::json::builder::PepJsonBuilder;
    /// use libpep::data::json::structure::JsonStructure;
    /// use libpep::elgamal::arithmetic::Ristretto255;
    /// use serde_json::json;
    ///
    /// let data = json!({
    ///     "id": "user@example.com",
    ///     "name": "Alice",
    ///     "age": 30
    /// });
    ///
    /// let builder = PepJsonBuilder::<Ristretto255>::from_json(&data, &["id"]).unwrap();
    /// let pep_value = builder.build();
    /// assert!(matches!(pep_value.structure(), JsonStructure::Object(_)));
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
        let pep_value = PepJsonValue::from_value(&value);
        self.fields.insert(key.to_string(), pep_value);
        self
    }

    /// Add a string field as a pseudonym: the identifier is PKCS#7-padded into one block when
    /// it fits (up to 15 bytes) and into a long pseudonym otherwise. Pseudonym values that
    /// already are group elements go in through [`pseudonym_hex`](Self::pseudonym_hex).
    pub fn pseudonym(mut self, key: &str, value: &str) -> Self {
        use crate::data::padding::Padded;
        use crate::data::simple::Pseudonym;

        let pseudonym = match Pseudonym::from_string_padded(value) {
            Ok(pseudonym) => PepJsonValue::Pseudonym(pseudonym),
            Err(_) => PepJsonValue::LongPseudonym(LongPseudonym::from_string_padded(value)),
        };
        self.fields.insert(key.to_string(), pseudonym);
        self
    }

    /// Add a pseudonym given as the hex encoding of its group elements: 64 hex digits for one
    /// block, a multiple of 64 for a long pseudonym. Returns `None` if the string is not such an
    /// encoding; identifiers go in through [`pseudonym`](Self::pseudonym).
    pub fn pseudonym_hex(mut self, key: &str, hex: &str) -> Option<Self> {
        use crate::data::elgamal::ElGamalEncryptable;
        use crate::data::simple::Pseudonym;

        if hex.is_empty() || !hex.len().is_multiple_of(64) {
            return None;
        }
        let blocks = hex
            .as_bytes()
            .chunks(64)
            .map(|chunk| Pseudonym::from_hex(std::str::from_utf8(chunk).ok()?))
            .collect::<Option<Vec<_>>>()?;
        let pseudonym = if blocks.len() == 1 {
            PepJsonValue::Pseudonym(blocks[0])
        } else {
            PepJsonValue::LongPseudonym(LongPseudonym(blocks))
        };
        self.fields.insert(key.to_string(), pseudonym);
        Some(self)
    }

    /// Build the final PepJsonValue object.
    pub fn build(self) -> PepJsonValue<G> {
        PepJsonValue::Object(self.fields)
    }
}

impl<G: InvertibleEncoding> Default for PepJsonBuilder<G> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::client::{decrypt, encrypt};
    use crate::contexts::EncryptionContext;
    use crate::elgamal::arithmetic::Ristretto255;
    use crate::elgamal::arithmetic::Ristretto255Sha512;
    use crate::factors::EncryptionSecret;
    use crate::keys::{
        make_attribute_global_keys, make_attribute_session_keys, make_pseudonym_global_keys,
        make_pseudonym_session_keys, AttributeSessionKeys, PseudonymSessionKeys, SessionKeys,
    };
    use serde_json::json;

    type PepJsonValue = crate::data::json::data::PepJsonValue<Ristretto255>;
    type PepJsonBuilder = super::PepJsonBuilder<Ristretto255>;

    fn make_test_keys() -> SessionKeys<Ristretto255> {
        let mut rng = rand::rng();
        let (_, attr_global_secret) = make_attribute_global_keys(&mut rng);
        let (_, pseudo_global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");

        let (attr_public, attr_secret) = make_attribute_session_keys::<Ristretto255Sha512>(
            &attr_global_secret,
            &session,
            &enc_secret,
        );
        let (pseudo_public, pseudo_secret) = make_pseudonym_session_keys::<Ristretto255Sha512>(
            &pseudo_global_secret,
            &session,
            &enc_secret,
        );

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

        let pep_value = PepJsonBuilder::new()
            .pseudonym("id", "user1@example.com")
            .attribute("age", json!(16))
            .attribute("verified", json!(true))
            .attribute("scores", json!([88, 91, 85]))
            .build();

        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
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
    fn builder_empty_object() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PepJsonBuilder::new().build();

        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        assert_eq!(json!({}), decrypted.to_value().unwrap());
    }

    #[test]
    fn builder_only_attributes() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PepJsonBuilder::new()
            .attribute("name", json!("Alice"))
            .attribute("age", json!(30))
            .build();

        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

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

        let pep_value = PepJsonBuilder::new()
            .pseudonym("id1", "user1@example.com")
            .pseudonym("id2", "user2@example.com")
            .build();

        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

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

        let pep_value = PepJsonBuilder::from_json(&data, &["id"]).unwrap().build();

        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

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

        let pep_value = PepJsonBuilder::from_json(&data, &["user_id", "email"])
            .unwrap()
            .build();

        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

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

        let pep_value = PepJsonBuilder::from_json(&data, &[]).unwrap().build();

        let encrypted = encrypt(&pep_value, &keys.public(), &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

        assert_eq!(data, decrypted.to_value().unwrap());
    }

    #[test]
    fn from_json_empty_object() {
        let data = json!({});

        let pep_value = PepJsonBuilder::from_json(&data, &[]).unwrap().build();

        // Just verify it can be built
        assert!(matches!(pep_value, PepJsonValue::Object(_)));
    }

    #[test]
    fn from_json_non_object_returns_none() {
        let data = json!([1, 2, 3]);
        assert!(PepJsonBuilder::from_json(&data, &[]).is_none());

        let data = json!("string");
        assert!(PepJsonBuilder::from_json(&data, &[]).is_none());

        let data = json!(42);
        assert!(PepJsonBuilder::from_json(&data, &[]).is_none());
    }

    #[test]
    fn from_json_pseudonym_not_string_returns_none() {
        let data = json!({
            "id": 123,
            "name": "Alice"
        });

        // "id" should be a pseudonym but it's not a string
        assert!(PepJsonBuilder::from_json(&data, &["id"]).is_none());
    }
}
