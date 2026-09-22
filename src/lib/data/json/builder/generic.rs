//! Builder for [`PEPJSONValue`]s generic over the [`Group`](crate::elgamal::arithmetic::Group).

use serde_json::Value;
use std::collections::HashMap;

use crate::data::json::data::generic::PEPJSONValue;
#[cfg(feature = "long")]
use crate::data::long::generic::LongPseudonym;
use crate::elgamal::arithmetic::group::InvertibleEncoding;

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
/// let encrypted = encrypt(&pep_value, &keys, &mut rng);
/// ```
pub struct PEPJSONBuilder<G: InvertibleEncoding> {
    fields: HashMap<String, PEPJSONValue<G>>,
}

impl<G: InvertibleEncoding> PEPJSONBuilder<G> {
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
        use crate::data::padding::Padded;
        use crate::data::simple::generic::Pseudonym;
        use crate::data::simple::ElGamalEncryptable;

        // Try to decode as a direct 32-byte pseudonym value (hex string)
        if let Some(pseudo) = Pseudonym::from_hex(value) {
            self.fields
                .insert(key.to_string(), PEPJSONValue::Pseudonym(pseudo));
            return self;
        }

        // Try to decode as multi-block pseudonym (hex string with multiple 64-char blocks)
        // Each block is 32 bytes = 64 hex chars
        if value.len() > 64 && value.len() % 64 == 0 {
            let num_blocks = value.len() / 64;
            let mut blocks = Vec::with_capacity(num_blocks);
            let mut all_decoded = true;

            for i in 0..num_blocks {
                let start = i * 64;
                let end = start + 64;
                if let Some(block) = Pseudonym::from_hex(&value[start..end]) {
                    blocks.push(block);
                } else {
                    all_decoded = false;
                    break;
                }
            }

            if all_decoded {
                self.fields.insert(
                    key.to_string(),
                    PEPJSONValue::LongPseudonym(LongPseudonym(blocks)),
                );
                return self;
            }
        }

        // Try to decode as 32 raw bytes
        if value.len() == 32 {
            if let Some(pseudo) = Pseudonym::from_slice(value.as_bytes()) {
                self.fields
                    .insert(key.to_string(), PEPJSONValue::Pseudonym(pseudo));
                return self;
            }
        }

        // Try to decode as multi-block pseudonym (raw bytes, multiple of 32)
        let bytes = value.as_bytes();
        if bytes.len() > 32 && bytes.len() % 32 == 0 {
            let num_blocks = bytes.len() / 32;
            let mut blocks = Vec::with_capacity(num_blocks);
            let mut all_decoded = true;

            for i in 0..num_blocks {
                let start = i * 32;
                let end = start + 32;
                if let Some(block) = Pseudonym::from_slice(&bytes[start..end]) {
                    blocks.push(block);
                } else {
                    all_decoded = false;
                    break;
                }
            }

            if all_decoded {
                self.fields.insert(
                    key.to_string(),
                    PEPJSONValue::LongPseudonym(LongPseudonym(blocks)),
                );
                return self;
            }
        }

        // Check if it fits in a single block with PKCS#7 padding (≤15 bytes)
        if bytes.len() <= 15 {
            // Use PKCS#7 padding for short strings
            match Pseudonym::from_string_padded(value) {
                Ok(pseudo) => {
                    self.fields
                        .insert(key.to_string(), PEPJSONValue::Pseudonym(pseudo));
                }
                Err(_) => {
                    // Fallback to long pseudonym if padding fails
                    let pseudo = LongPseudonym::from_string_padded(value);
                    self.fields
                        .insert(key.to_string(), PEPJSONValue::LongPseudonym(pseudo));
                }
            }
        } else {
            // Use long pseudonym for strings > 15 bytes
            let pseudo = LongPseudonym::from_string_padded(value);
            self.fields
                .insert(key.to_string(), PEPJSONValue::LongPseudonym(pseudo));
        }

        self
    }

    /// Build the final PEPJSONValue object.
    pub fn build(self) -> PEPJSONValue<G> {
        PEPJSONValue::Object(self.fields)
    }
}

impl<G: InvertibleEncoding> Default for PEPJSONBuilder<G> {
    fn default() -> Self {
        Self::new()
    }
}
