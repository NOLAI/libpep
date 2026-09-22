//! Builder pattern for constructing PEPJSONValue objects.
//!
//! The builder is generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the name in this module is its ristretto255 instance.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`PEPJSONBuilder`](generic::PEPJSONBuilder) over ristretto255.
pub type PEPJSONBuilder = generic::PEPJSONBuilder<Ristretto255>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::{decrypt, encrypt};
    use crate::contexts::EncryptionContext;
    use crate::data::json::data::PEPJSONValue;
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
    fn builder_with_pseudonym_id() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PEPJSONBuilder::new()
            .pseudonym("id", "user1@example.com")
            .attribute("age", json!(16))
            .attribute("verified", json!(true))
            .attribute("scores", json!([88, 91, 85]))
            .build();

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
    fn builder_empty_object() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = PEPJSONBuilder::new().build();

        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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

        let pep_value = PEPJSONBuilder::new()
            .attribute("name", json!("Alice"))
            .attribute("age", json!(30))
            .build();

        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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

        let pep_value = PEPJSONBuilder::new()
            .pseudonym("id1", "user1@example.com")
            .pseudonym("id2", "user2@example.com")
            .build();

        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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

        let pep_value = PEPJSONBuilder::from_json(&data, &["id"]).unwrap().build();

        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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

        let pep_value = PEPJSONBuilder::from_json(&data, &["user_id", "email"])
            .unwrap()
            .build();

        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
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

        let pep_value = PEPJSONBuilder::from_json(&data, &[]).unwrap().build();

        let encrypted = encrypt(&pep_value, &keys.public_keys(), &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &keys).unwrap();

        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &keys);

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
