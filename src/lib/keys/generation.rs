//! Key generation functions for global and session keys.
//!
//! The generation is generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]. The functions that take key material infer the group from it and are the
//! generic ones; the functions that generate global keys from randomness alone are ristretto255
//! instances, as there is nothing to infer the group from.

pub mod generic;

pub use generic::{
    make_attribute_session_keys, make_global_key_pair, make_pseudonym_session_keys,
    make_session_keys,
};
#[cfg(feature = "verifiable")]
pub use generic::{
    make_attribute_session_keys_with_proof, make_pseudonym_session_keys_with_proof,
    make_session_key_pair_with_proof, SessionKeyShareError,
};

use super::types::*;
use rand_core::{CryptoRng, Rng};

/// Generate new global key pairs for both pseudonyms and attributes.
pub fn make_global_keys<R: Rng + CryptoRng>(rng: &mut R) -> (GlobalPublicKeys, GlobalSecretKeys) {
    generic::make_global_keys(rng)
}

/// Generate a new global key pair for pseudonyms.
pub fn make_pseudonym_global_keys<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (PseudonymGlobalPublicKey, PseudonymGlobalSecretKey) {
    generic::make_pseudonym_global_keys(rng)
}

/// Generate a new global key pair for attributes.
pub fn make_attribute_global_keys<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (AttributeGlobalPublicKey, AttributeGlobalSecretKey) {
    generic::make_attribute_global_keys(rng)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::contexts::EncryptionContext;
    #[cfg(feature = "verifiable")]
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    #[cfg(feature = "verifiable")]
    use crate::elgamal::verifiable::RekeyFactorCommitment;
    use crate::factors::EncryptionSecret;
    #[cfg(feature = "verifiable")]
    use crate::factors::{make_attribute_rekey_factor, make_pseudonym_rekey_factor, Factor};
    #[cfg(feature = "verifiable")]
    use crate::keys::distribution::BlindingFactor;
    use crate::keys::traits::SecretKey;
    // `public_key()`.
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::keys::traits::PublicKey;

    #[test]
    fn make_global_keys_creates_valid_keypairs() {
        let mut rng = rand::rng();
        let (public, secret) = make_global_keys(&mut rng);

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
    fn public_key_matches_derivation() {
        let mut rng = rand::rng();
        let (public, secret) = make_pseudonym_global_keys(&mut rng);
        assert_eq!(public, secret.public_key());
    }

    #[test]
    fn make_session_keys_derives_from_global() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());

        let session = make_session_keys(&global_sk, &context, &secret);

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
        let mut rng = rand::rng();
        let (public, _) = make_pseudonym_global_keys(&mut rng);
        let encoded = public.to_bytes();
        let decoded =
            PseudonymGlobalPublicKey::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(public, decoded);
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let mut rng = rand::rng();
        let (public, _) = make_attribute_global_keys(&mut rng);
        let hex = public.to_hex();
        let decoded =
            AttributeGlobalPublicKey::from_hex(&hex).expect("hex decoding should succeed");
        assert_eq!(public, decoded);
    }

    #[test]
    #[cfg(feature = "verifiable")]
    fn session_keys_with_proof_verify() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let session = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());
        let blinding = BlindingFactor::random(&mut rng);

        let (_pk, _sk, proof, commitment) = make_pseudonym_session_keys_with_proof(
            &global_sk.pseudonym,
            &session,
            &secret,
            &blinding,
            &mut rng,
        )
        .unwrap();
        let k = make_pseudonym_rekey_factor(&secret, &session);
        assert!(proof.verify(
            &commitment,
            &RekeyFactorCommitment::new(&k.scalar()).point()
        ));
        assert_eq!(*commitment.value(), *blinding.value() * G);

        let (_pk, _sk, proof, commitment) = make_attribute_session_keys_with_proof(
            &global_sk.attribute,
            &session,
            &secret,
            &blinding,
            &mut rng,
        )
        .unwrap();
        let k = make_attribute_rekey_factor(&secret, &session);
        assert!(proof.verify(
            &commitment,
            &RekeyFactorCommitment::new(&k.scalar()).point()
        ));
    }

    #[test]
    #[cfg(feature = "verifiable")]
    fn session_keys_with_proof_reject_unit_blinding() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let session = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());
        let blinding = BlindingFactor::from_scalar(ScalarNonZero::one());
        assert_eq!(
            make_pseudonym_session_keys_with_proof(
                &global_sk.pseudonym,
                &session,
                &secret,
                &blinding,
                &mut rng
            )
            .err(),
            Some(SessionKeyShareError::WeakBlinding)
        );
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
