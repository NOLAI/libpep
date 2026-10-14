//! Builder for [`PepJsonValue`]s generic over the [`Group`](crate::elgamal::arithmetic::Group).

use serde_json::Value;
use std::collections::BTreeMap;

use crate::data::json::data::generic::PepJsonValue;
use crate::data::long::generic::LongPseudonym;
use crate::elgamal::arithmetic::group::InvertibleEncoding;

/// Builder for constructing PepJsonValue objects with mixed attribute and pseudonym fields.
///
/// # Example
///
/// ```ignore
/// let pep_value = PepJsonBuilder::new()
///     .pseudonym("id", "user1@example.com")
///     .attribute("age", json!(16))
///     .attribute("verified", json!(true))
///     .attribute("scores", json!([88, 91, 85]))
///     .build();
///
/// // Then encrypt it
/// let encrypted = encrypt(&pep_value, &keys, &mut rng);
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
    /// ```ignore
    /// use serde_json::json;
    ///
    /// let data = json!({
    ///     "id": "user@example.com",
    ///     "name": "Alice",
    ///     "age": 30
    /// });
    ///
    /// let builder = PepJsonBuilder::from_json(&data, &["id"]).unwrap();
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
        let pep_value = PepJsonValue::from_value(&value);
        self.fields.insert(key.to_string(), pep_value);
        self
    }

    /// Add a string field as a pseudonym: the identifier is PKCS#7-padded into one block when
    /// it fits (up to 15 bytes) and into a long pseudonym otherwise. Pseudonym values that
    /// already are group elements go in through [`pseudonym_hex`](Self::pseudonym_hex).
    pub fn pseudonym(mut self, key: &str, value: &str) -> Self {
        use crate::data::padding::Padded;
        use crate::data::simple::generic::Pseudonym;

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
        use crate::data::simple::generic::Pseudonym;
        use crate::data::simple::ElGamalEncryptable;

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
