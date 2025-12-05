//! Transcryption operations for EncryptedPEPJSONValue.

use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

use super::data::EncryptedPEPJSONValue;
#[cfg(test)]
use super::data::{decrypt_json, encrypt_json};
use crate::core::long::transcryption::{transcrypt_long_attribute, transcrypt_long_pseudonym};
use crate::core::transcryption::contexts::TranscryptionInfo;
use crate::core::transcryption::ops::transcrypt_attribute;

impl EncryptedPEPJSONValue {
    /// Transcrypt this EncryptedPEPJSONValue from one context to another.
    ///
    /// This transcrypts all encrypted attributes and pseudonyms in the value,
    /// applying both rekeying (for attributes) and pseudonymization (for pseudonyms).
    pub fn transcrypt(&self, transcryption_info: &TranscryptionInfo) -> Self {
        match self {
            EncryptedPEPJSONValue::Null => EncryptedPEPJSONValue::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                EncryptedPEPJSONValue::Bool(transcrypt_attribute(enc, transcryption_info))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                EncryptedPEPJSONValue::Number(transcrypt_attribute(enc, transcryption_info))
            }
            EncryptedPEPJSONValue::String(enc) => {
                EncryptedPEPJSONValue::String(transcrypt_long_attribute(enc, transcryption_info))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => {
                EncryptedPEPJSONValue::Pseudonym(transcrypt_long_pseudonym(enc, transcryption_info))
            }
            EncryptedPEPJSONValue::Array(arr) => {
                let transcrypted = arr
                    .iter()
                    .map(|item| item.transcrypt(transcryption_info))
                    .collect();
                EncryptedPEPJSONValue::Array(transcrypted)
            }
            EncryptedPEPJSONValue::Object(obj) => {
                let transcrypted = obj
                    .iter()
                    .map(|(key, val)| (key.clone(), val.transcrypt(transcryption_info)))
                    .collect();
                EncryptedPEPJSONValue::Object(transcrypted)
            }
        }
    }
}

/// Transcrypt an EncryptedPEPJSONValue from one context to another.
///
/// This transcrypts all encrypted attributes and pseudonyms in the value,
/// applying both rekeying (for attributes) and pseudonymization (for pseudonyms).
pub fn transcrypt_json(
    value: &EncryptedPEPJSONValue,
    transcryption_info: &TranscryptionInfo,
) -> EncryptedPEPJSONValue {
    value.transcrypt(transcryption_info)
}

#[cfg(feature = "batch")]
/// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
///
/// This is useful for unlinkability - the shuffled order prevents correlation
/// between input and output based on position.
///
/// # Errors
///
/// Returns an error if the values do not all have the same structure.
pub fn transcrypt_json_batch<R: RngCore + CryptoRng>(
    mut values: Vec<EncryptedPEPJSONValue>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Result<Vec<EncryptedPEPJSONValue>, String> {
    // Verify all values have the same structure
    if let Some(first) = values.first() {
        let first_structure = first.structure();
        for (index, value) in values.iter().enumerate().skip(1) {
            if first_structure != value.structure() {
                return Err(format!(
                    "All values must have the same structure. Value at index {} has a different structure.",
                    index
                ));
            }
        }
    }

    // Shuffle first for efficiency
    values.shuffle(rng);

    // Then transcrypt
    let transcrypted: Vec<EncryptedPEPJSONValue> = values
        .iter()
        .map(|v| v.transcrypt(transcryption_info))
        .collect();

    Ok(transcrypted)
}

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
    use crate::pep_json;
    use serde_json::json;

    fn make_transcryption_info() -> (SessionKeys, SessionKeys, TranscryptionInfo) {
        use crate::core::transcryption::contexts::PseudonymizationDomain;
        use crate::core::transcryption::secrets::PseudonymizationSecret;

        let mut rng = rand::rng();
        let (_, attr_global_secret) = make_attribute_global_keys(&mut rng);
        let (_, pseudo_global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let pseudo_secret = PseudonymizationSecret::from("pseudo-secret".as_bytes().to_vec());

        let from_session = EncryptionContext::from("session-from");
        let to_session = EncryptionContext::from("session-to");
        let from_domain = PseudonymizationDomain::from("domain-from");
        let to_domain = PseudonymizationDomain::from("domain-to");

        let (from_attr_public, from_attr_secret) =
            make_attribute_session_keys(&attr_global_secret, &from_session, &enc_secret);
        let (from_pseudo_public, from_pseudo_secret) =
            make_pseudonym_session_keys(&pseudo_global_secret, &from_session, &enc_secret);

        let (to_attr_public, to_attr_secret) =
            make_attribute_session_keys(&attr_global_secret, &to_session, &enc_secret);
        let (to_pseudo_public, to_pseudo_secret) =
            make_pseudonym_session_keys(&pseudo_global_secret, &to_session, &enc_secret);

        let from_keys = SessionKeys {
            attribute: AttributeSessionKeys {
                public: from_attr_public,
                secret: from_attr_secret,
            },
            pseudonym: PseudonymSessionKeys {
                public: from_pseudo_public,
                secret: from_pseudo_secret,
            },
        };

        let to_keys = SessionKeys {
            attribute: AttributeSessionKeys {
                public: to_attr_public,
                secret: to_attr_secret,
            },
            pseudonym: PseudonymSessionKeys {
                public: to_pseudo_public,
                secret: to_pseudo_secret,
            },
        };

        let transcryption_info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            &from_session,
            &to_session,
            &pseudo_secret,
            &enc_secret,
        );

        (from_keys, to_keys, transcryption_info)
    }

    #[test]
    fn transcrypt_simple_value() {
        let mut rng = rand::rng();
        let (from_keys, to_keys, transcryption_info) = make_transcryption_info();

        let pep_value = pep_json!({
            "name": "Alice",
            "age": 30
        });

        let encrypted = encrypt_json(&pep_value, &from_keys, &mut rng);
        let transcrypted = encrypted.transcrypt(&transcryption_info);
        let decrypted = decrypt_json(&transcrypted, &to_keys).unwrap();

        let expected = json!({
            "name": "Alice",
            "age": 30
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    #[test]
    fn transcrypt_with_pseudonym() {
        let mut rng = rand::rng();
        let (from_keys, to_keys, transcryption_info) = make_transcryption_info();

        let pep_value = pep_json!({
            "id": pseudonym("user@example.com"),
            "name": "Alice",
            "age": 30
        });

        let encrypted = encrypt_json(&pep_value, &from_keys, &mut rng);
        let transcrypted = encrypted.transcrypt(&transcryption_info);

        let decrypted = decrypt_json(&transcrypted, &to_keys).unwrap();

        // Verify the pseudonym changed (as hex representation)
        let decrypted_json = decrypted.to_value().unwrap();
        let pseudonym_hex = decrypted_json["id"].as_str().unwrap();

        // The pseudonym is deterministic based on:
        // - Original value: "user@example.com"
        // - From domain: "domain-from"
        // - To domain: "domain-to"
        // - Pseudonymization secret: "pseudo-secret"
        assert_ne!(
            pseudonym_hex, "user@example.com",
            "Pseudonym should be different after transcryption to different domain"
        );

        #[cfg(feature = "legacy")]
        assert_eq!(
            pseudonym_hex,
            "3e9f94d1796939e7089945a7c561f37f31174063cee572172cf81b4069ad247cb68549768010949c1422fe4d611d45fb5cfe84c474b4d1493f36735df5a19066",
            "Pseudonym should be deterministic and match expected value"
        );
        #[cfg(not(feature = "legacy"))]
        assert_eq!(
            pseudonym_hex,
            "cec249944578c90ade517b34327e5210b479dbf3efaf5b0cf1d9f559f8f42b788e10050b9fa3dbe245f6843d8eb03e38c1d368914b0a89c7323adca4860f0a48",
            "Pseudonym should be deterministic and match expected value"
        );

        // Verify regular attributes remain the same
        assert_eq!(decrypted_json["name"], "Alice");
        assert_eq!(decrypted_json["age"], 30);
    }

    #[test]
    fn transcrypt_nested() {
        let mut rng = rand::rng();
        let (from_keys, to_keys, transcryption_info) = make_transcryption_info();

        let pep_value = pep_json!({
            "user": {"name": "Alice", "active": true},
            "scores": [88, 91, 85]
        });

        let encrypted = encrypt_json(&pep_value, &from_keys, &mut rng);
        let transcrypted = encrypted.transcrypt(&transcryption_info);
        let decrypted = decrypt_json(&transcrypted, &to_keys).unwrap();

        let expected = json!({
            "user": {"name": "Alice", "active": true},
            "scores": [88, 91, 85]
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    #[test]
    fn batch_transcrypt_shuffles() {
        let mut rng = rand::rng();
        let (from_keys, to_keys, transcryption_info) = make_transcryption_info();

        // Create a batch of values
        let values: Vec<EncryptedPEPJSONValue> = (0..10)
            .map(|i| {
                let pep_value = pep_json!({
                    "id": pseudonym(format!("user{}@example.com", i).as_str()),
                    "index": (i as i64)
                });
                encrypt_json(&pep_value, &from_keys, &mut rng)
            })
            .collect();

        // Decrypt values before transcryption to get original pseudonym values
        let original_pseudonyms: Vec<String> = values
            .iter()
            .map(|v| {
                let decrypted = decrypt_json(v, &from_keys).unwrap();
                let json = decrypted.to_value().unwrap();
                json["id"].as_str().unwrap().to_string()
            })
            .collect();

        let transcrypted = transcrypt_json_batch(values, &transcryption_info, &mut rng).unwrap();

        // Verify all values are present (but possibly in different order)
        assert_eq!(transcrypted.len(), 10);

        // Decrypt all values
        let mut decrypted: Vec<serde_json::Value> = transcrypted
            .iter()
            .map(|v| decrypt_json(v, &to_keys).unwrap().to_value().unwrap())
            .collect();

        // Sort by index to compare
        decrypted.sort_by_key(|v| v["index"].as_i64().unwrap());

        for (i, v) in decrypted.iter().enumerate() {
            // Verify the pseudonym value changed after transcryption to different domain
            let pseudonym_after = v["id"].as_str().unwrap();
            assert_ne!(
                &original_pseudonyms[i], pseudonym_after,
                "Pseudonym should be different after transcryption to different domain"
            );
            assert_eq!(v["index"], i as i64);
        }
    }
}
