//! Macros for creating PEPJSONValue objects with a JSON-like syntax.

/// Macro for creating PEPJSONValue objects with a JSON-like syntax.
///
/// Supports marking fields as pseudonyms using `pseudonym("value")` syntax.
/// Creates an unencrypted `PEPJSONValue` which can then be encrypted.
///
/// # Example
///
/// ```ignore
/// use libpep::pep_json;
/// use serde_json::json;
///
/// let pep_value = pep_json!({
///     "id": pseudonym("user1@example.com"),
///     "age": 16,
///     "verified": true,
///     "scores": [88, 91, 85]
/// });
///
/// // Then encrypt it
/// let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
/// let decrypted = decrypt_json(&encrypted, &keys)?;
/// assert_eq!(decrypted, json!({
///     "id": "user1@example.com",
///     "age": 16,
///     "verified": true,
///     "scores": [88, 91, 85]
/// }));
/// ```
#[macro_export]
macro_rules! pep_json {
    // Entry point for object
    ({ $($tt:tt)* }) => {{
        let builder = $crate::core::json::builder::PEPJSONBuilder::new();
        pep_json!(@object builder, $($tt)*)
    }};

    // Parse object fields - empty
    (@object $builder:ident, ) => {
        $builder.build()
    };

    // Pseudonym field (last field, no trailing comma)
    (@object $builder:ident, $key:literal : pseudonym($value:expr)) => {{
        $builder.pseudonym($key, $value).build()
    }};

    // Pseudonym field with more fields following
    (@object $builder:ident, $key:literal : pseudonym($value:expr), $($rest:tt)*) => {{
        let builder = $builder.pseudonym($key, $value);
        pep_json!(@object builder, $($rest)*)
    }};

    // Object field (last field, no trailing comma)
    (@object $builder:ident, $key:literal : { $($inner:tt)* }) => {{
        $builder.attribute($key, serde_json::json!({ $($inner)* })).build()
    }};

    // Object field with more fields following
    (@object $builder:ident, $key:literal : { $($inner:tt)* }, $($rest:tt)*) => {{
        let builder = $builder.attribute($key, serde_json::json!({ $($inner)* }));
        pep_json!(@object builder, $($rest)*)
    }};

    // Array field (last field, no trailing comma)
    (@object $builder:ident, $key:literal : [ $($inner:tt)* ]) => {{
        $builder.attribute($key, serde_json::json!([ $($inner)* ])).build()
    }};

    // Array field with more fields following
    (@object $builder:ident, $key:literal : [ $($inner:tt)* ], $($rest:tt)*) => {{
        let builder = $builder.attribute($key, serde_json::json!([ $($inner)* ]));
        pep_json!(@object builder, $($rest)*)
    }};

    // Regular field (last field, no trailing comma)
    (@object $builder:ident, $key:literal : $value:expr) => {{
        $builder.attribute($key, serde_json::json!($value)).build()
    }};

    // Regular field with more fields following
    (@object $builder:ident, $key:literal : $value:expr, $($rest:tt)*) => {{
        let builder = $builder.attribute($key, serde_json::json!($value));
        pep_json!(@object builder, $($rest)*)
    }};
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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
    fn macro_with_pseudonym_id() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = pep_json!({
            "id": pseudonym("user1@example.com"),
            "age": 16,
            "verified": true,
            "scores": [88, 91, 85]
        });

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
    fn macro_only_attributes() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = pep_json!({
            "name": "Alice",
            "age": 30
        });

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        let expected = json!({
            "name": "Alice",
            "age": 30
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    #[test]
    fn macro_empty_object() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = pep_json!({});

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        assert_eq!(json!({}), decrypted.to_value().unwrap());
    }

    #[test]
    fn macro_multiple_pseudonyms() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = pep_json!({
            "id1": pseudonym("user1@example.com"),
            "id2": pseudonym("user2@example.com")
        });

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        let expected = json!({
            "id1": "user1@example.com",
            "id2": "user2@example.com"
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }

    #[test]
    fn macro_nested_values() {
        let mut rng = rand::rng();
        let keys = make_test_keys();

        let pep_value = pep_json!({
            "user": {"name": "Alice", "active": true},
            "scores": [1, 2, 3]
        });

        let encrypted = encrypt_json(&pep_value, &keys, &mut rng);
        let decrypted = decrypt_json(&encrypted, &keys).unwrap();

        let expected = json!({
            "user": {
                "name": "Alice",
                "active": true
            },
            "scores": [1, 2, 3]
        });

        assert_eq!(expected, decrypted.to_value().unwrap());
    }
}
