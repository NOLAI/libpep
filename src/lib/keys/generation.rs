//! Key generation functions for global and session keys.

use super::traits::SecretKey;
use super::types::*;
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use crate::factors::contexts::EncryptionContext;
use crate::factors::RekeyFactor;
use crate::factors::{make_attribute_rekey_factor, make_pseudonym_rekey_factor, EncryptionSecret};
use rand_core::{CryptoRng, Rng};

/// Polymorphic function to generate a global key pair.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn make_global_key_pair<R, SK>(rng: &mut R) -> (SK::PublicKeyType, SK)
where
    R: Rng + CryptoRng,
    SK: SecretKey,
{
    let scalar = loop {
        let scalar = ScalarNonZero::random(rng);
        if scalar != ScalarNonZero::one() {
            break scalar;
        }
    };
    let sk = SK::from_scalar(scalar);
    (sk.public_key(), sk)
}

/// Generate new global key pairs for both pseudonyms and attributes.
pub fn make_global_keys<R: Rng + CryptoRng>(rng: &mut R) -> (GlobalPublicKeys, GlobalSecretKeys) {
    let (pseudonym_pk, pseudonym_sk) = make_global_key_pair(rng);
    let (attribute_pk, attribute_sk) = make_global_key_pair(rng);
    (
        GlobalPublicKeys {
            pseudonym: pseudonym_pk,
            attribute: attribute_pk,
        },
        GlobalSecretKeys {
            pseudonym: pseudonym_sk,
            attribute: attribute_sk,
        },
    )
}

/// Generate a new global key pair for pseudonyms.
/// This is a convenience wrapper around [`make_global_key_pair`].
pub fn make_pseudonym_global_keys<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (PseudonymGlobalPublicKey, PseudonymGlobalSecretKey) {
    make_global_key_pair(rng)
}

/// Generate a new global key pair for attributes.
/// This is a convenience wrapper around [`make_global_key_pair`].
pub fn make_attribute_global_keys<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (AttributeGlobalPublicKey, AttributeGlobalSecretKey) {
    make_global_key_pair(rng)
}

/// Polymorphic function to generate a session key pair from a global secret key.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn make_session_key_pair<GSK, SK, RF, F>(
    global: &GSK,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
    rekey_fn: F,
) -> (SK::PublicKeyType, SK)
where
    GSK: SecretKey,
    SK: SecretKey,
    RF: RekeyFactor,
    F: Fn(&EncryptionSecret, &EncryptionContext) -> RF,
{
    let k = rekey_fn(secret, context);
    let sk = SK::from_scalar(k.scalar() * *global.value());
    (sk.public_key(), sk)
}

/// Generate session keys for both pseudonyms and attributes from [`GlobalSecretKeys`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_session_keys(
    global: &GlobalSecretKeys,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> SessionKeys {
    let (pseudonym_public, pseudonym_secret) = make_session_key_pair(
        &global.pseudonym,
        context,
        secret,
        make_pseudonym_rekey_factor,
    );
    let (attribute_public, attribute_secret) = make_session_key_pair(
        &global.attribute,
        context,
        secret,
        make_attribute_rekey_factor,
    );

    SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Generate session keys for pseudonyms from a [`PseudonymGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
/// This is a convenience wrapper around [`make_session_key_pair`].
pub fn make_pseudonym_session_keys(
    global: &PseudonymGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    make_session_key_pair(global, context, secret, make_pseudonym_rekey_factor)
}

/// Generate session keys for attributes from an [`AttributeGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
/// This is a convenience wrapper around [`make_session_key_pair`].
pub fn make_attribute_session_keys(
    global: &AttributeGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    make_session_key_pair(global, context, secret, make_attribute_rekey_factor)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    // The basepoint is imported here so the assertions verify the derivation independently,
    // rather than comparing `public_key()` against itself.
    use crate::elgamal::arithmetic::group_elements::G;

    #[test]
    fn make_global_keys_creates_valid_keypairs() {
        let mut rng = rand::rng();
        let (public, secret) = make_global_keys(&mut rng);

        // Verify public key matches secret key
        assert_eq!(*public.pseudonym, *secret.pseudonym.value() * G);
        assert_eq!(*public.attribute, *secret.attribute.value() * G);
    }

    #[test]
    fn make_pseudonym_global_keys_creates_valid_keypair() {
        let mut rng = rand::rng();
        let (public, secret) = make_global_key_pair::<_, PseudonymGlobalSecretKey>(&mut rng);
        assert_eq!(*public, *secret.value() * G);
    }

    #[test]
    fn make_attribute_global_keys_creates_valid_keypair() {
        let mut rng = rand::rng();
        let (public, secret) = make_global_key_pair::<_, AttributeGlobalSecretKey>(&mut rng);
        assert_eq!(*public, *secret.value() * G);
    }

    #[test]
    fn make_session_keys_derives_from_global() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());

        let session = make_session_keys(&global_sk, &context, &secret);

        // Verify session public keys match session secret keys
        assert_eq!(
            *session.pseudonym.public,
            *session.pseudonym.secret.value() * G
        );
        assert_eq!(
            *session.attribute.public,
            *session.attribute.secret.value() * G
        );
    }

    #[test]
    fn session_keys_deterministic() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());

        let session1 = make_session_keys(&global_sk, &context, &secret);
        let session2 = make_session_keys(&global_sk, &context, &secret);

        assert_eq!(session1, session2);
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let secret = EncryptionSecret::from(b"test-secret".to_vec());

        let session1 = make_session_keys(&global_sk, &EncryptionContext::from("context1"), &secret);
        let session2 = make_session_keys(&global_sk, &EncryptionContext::from("context2"), &secret);

        assert_ne!(session1, session2);
    }

    #[test]
    fn public_key_encode_decode() {
        use crate::keys::traits::PublicKey;
        let mut rng = rand::rng();
        let (public, _) = make_global_key_pair::<_, PseudonymGlobalSecretKey>(&mut rng);
        let encoded = public.to_bytes();
        let decoded =
            PseudonymGlobalPublicKey::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(public, decoded);
    }

    #[test]
    fn public_key_hex_roundtrip() {
        use crate::keys::traits::PublicKey;
        let mut rng = rand::rng();
        let (public, _) = make_global_key_pair::<_, AttributeGlobalSecretKey>(&mut rng);
        let hex = public.to_hex();
        let decoded =
            AttributeGlobalPublicKey::from_hex(&hex).expect("hex decoding should succeed");
        assert_eq!(public, decoded);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn session_secret_key_serde() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test");
        let secret = EncryptionSecret::from(b"secret".to_vec());

        let session = make_session_keys(&global_sk, &context, &secret);

        let json =
            serde_json::to_string(&session.pseudonym.secret).expect("serialization should succeed");
        let deserialized: PseudonymSessionSecretKey =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(session.pseudonym.secret, deserialized);
    }
}
