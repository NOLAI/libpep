//! Transcryption operations for EncryptedPEPJSONValue.

use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

use super::core::EncryptedPEPJSONValue;
use crate::core::long::ops::{transcrypt_long_attribute, transcrypt_long_pseudonym};
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

/// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
///
/// This is useful for unlinkability - the shuffled order prevents correlation
/// between input and output based on position.
pub fn transcrypt_batch<R: RngCore + CryptoRng>(
    values: Vec<EncryptedPEPJSONValue>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Vec<EncryptedPEPJSONValue> {
    let mut transcrypted: Vec<EncryptedPEPJSONValue> = values
        .iter()
        .map(|v| v.transcrypt(transcryption_info))
        .collect();

    transcrypted.shuffle(rng);
    transcrypted
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
        // Use same domain so pseudonyms decrypt to same value (for testing)
        let from_domain = PseudonymizationDomain::from("domain");
        let to_domain = PseudonymizationDomain::from("domain");

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

        #[cfg(feature = "global")]
        let transcryption_info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            Some(&from_session),
            Some(&to_session),
            &pseudo_secret,
            &enc_secret,
        );

        #[cfg(not(feature = "global"))]
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

        let encrypted = pep_value.encrypt(&from_keys, &mut rng);
        let transcrypted = encrypted.transcrypt(&transcryption_info);
        let decrypted = transcrypted.decrypt(&to_keys).unwrap();

        let expected = json!({
            "name": "Alice",
            "age": 30
        });

        assert_eq!(expected, decrypted);
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

        let encrypted = pep_value.encrypt(&from_keys, &mut rng);
        let transcrypted = encrypted.transcrypt(&transcryption_info);
        let decrypted = transcrypted.decrypt(&to_keys).unwrap();

        let expected = json!({
            "id": "user@example.com",
            "name": "Alice",
            "age": 30
        });

        assert_eq!(expected, decrypted);
    }

    #[test]
    fn transcrypt_nested() {
        let mut rng = rand::rng();
        let (from_keys, to_keys, transcryption_info) = make_transcryption_info();

        let pep_value = pep_json!({
            "user": {"name": "Alice", "active": true},
            "scores": [88, 91, 85]
        });

        let encrypted = pep_value.encrypt(&from_keys, &mut rng);
        let transcrypted = encrypted.transcrypt(&transcryption_info);
        let decrypted = transcrypted.decrypt(&to_keys).unwrap();

        let expected = json!({
            "user": {"name": "Alice", "active": true},
            "scores": [88, 91, 85]
        });

        assert_eq!(expected, decrypted);
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
                pep_value.encrypt(&from_keys, &mut rng)
            })
            .collect();

        let transcrypted = transcrypt_batch(values, &transcryption_info, &mut rng);

        // Verify all values are present (but possibly in different order)
        assert_eq!(transcrypted.len(), 10);

        // Decrypt all values
        let mut decrypted: Vec<serde_json::Value> = transcrypted
            .iter()
            .map(|v| v.decrypt(&to_keys).unwrap())
            .collect();

        // Sort by index to compare
        decrypted.sort_by_key(|v| v["index"].as_i64().unwrap());

        for (i, v) in decrypted.iter().enumerate() {
            assert_eq!(v["id"], format!("user{}@example.com", i));
            assert_eq!(v["index"], i as i64);
        }
    }
}
