//! Key generation generic over the [`Group`].

use crate::contexts::EncryptionContext;
use crate::elgamal::arithmetic::group::Group;
use crate::factors::derivation::generic::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor,
};
use crate::factors::types::generic::RekeyFactor;
use crate::factors::EncryptionSecret;
use crate::keys::traits::SecretKey;
use crate::keys::types::generic::*;
use rand_core::{CryptoRng, Rng};

/// Generate a global key pair of the given secret key type.
///
/// The secret key is a random scalar other than one; the public key is derived from it with
/// [`SecretKey::public_key`].
pub fn make_global_key_pair<R, SK>(rng: &mut R) -> (SK::PublicKeyType, SK)
where
    R: Rng + CryptoRng,
    SK: SecretKey,
{
    let scalar = loop {
        let scalar = SK::Group::random_scalar(rng);
        if scalar != SK::Group::scalar_one() {
            break scalar;
        }
    };
    let sk = SK::from_scalar(scalar);
    (sk.public_key(), sk)
}

/// Generate new global key pairs for both pseudonyms and attributes.
pub fn make_global_keys<G: Group, R: Rng + CryptoRng>(
    rng: &mut R,
) -> (GlobalPublicKeys<G>, GlobalSecretKeys<G>) {
    let (pseudonym_pk, pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (attribute_pk, attribute_sk) = make_attribute_global_keys(rng);
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
pub fn make_pseudonym_global_keys<G: Group, R: Rng + CryptoRng>(
    rng: &mut R,
) -> (PseudonymGlobalPublicKey<G>, PseudonymGlobalSecretKey<G>) {
    make_global_key_pair(rng)
}

/// Generate a new global key pair for attributes.
pub fn make_attribute_global_keys<G: Group, R: Rng + CryptoRng>(
    rng: &mut R,
) -> (AttributeGlobalPublicKey<G>, AttributeGlobalSecretKey<G>) {
    make_global_key_pair(rng)
}

/// Generate session keys for both pseudonyms and attributes from [`GlobalSecretKeys`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_session_keys<G: Group>(
    global: &GlobalSecretKeys<G>,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> SessionKeys<G> {
    let (pseudonym_public, pseudonym_secret) =
        make_pseudonym_session_keys(&global.pseudonym, context, secret);
    let (attribute_public, attribute_secret) =
        make_attribute_session_keys(&global.attribute, context, secret);
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
///
/// The session secret key is the global secret key multiplied by the pseudonym rekey factor of
/// the context.
pub fn make_pseudonym_session_keys<G: Group>(
    global: &PseudonymGlobalSecretKey<G>,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (PseudonymSessionPublicKey<G>, PseudonymSessionSecretKey<G>) {
    let k = make_pseudonym_rekey_factor::<G>(secret, context);
    let sk = PseudonymSessionSecretKey::from_scalar(k.scalar() * *global.value());
    (sk.public_key(), sk)
}

/// Generate session keys for attributes from an [`AttributeGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
///
/// The session secret key is the global secret key multiplied by the attribute rekey factor of
/// the context.
pub fn make_attribute_session_keys<G: Group>(
    global: &AttributeGlobalSecretKey<G>,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (AttributeSessionPublicKey<G>, AttributeSessionSecretKey<G>) {
    let k = make_attribute_rekey_factor::<G>(secret, context);
    let sk = AttributeSessionSecretKey::from_scalar(k.scalar() * *global.value());
    (sk.public_key(), sk)
}
