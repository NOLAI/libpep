//! Polymorphic encryption and decryption helper functions for client operations.

use crate::data::traits::{Encryptable, Encrypted};
use crate::group::Group;
use crate::keys::KeyProvider;
use rand_core::{CryptoRng, Rng};

/// Polymorphic encrypt function that works for any encryptable type.
///
/// `key` is either the one key this message type is encrypted under, or a bundle to take it from
/// (see [`KeyProvider`]); the message type decides which key is used.
///
/// # Examples
/// ```
/// # use libpep::client::encrypt;
/// # use libpep::contexts::EncryptionContext;
/// # use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
/// # use libpep::group::Ristretto255;
/// # use libpep::factors::RekeyingSecret;
/// # use libpep::keys::{make_global_keys, make_session_keys};
/// # use libpep::ciphersuite::Ristretto255Sha512;
/// # let rng = &mut rand::rng();
/// # let (_global_public, global_secret) = make_global_keys(rng);
/// # let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
/// # let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
/// let pseudonym = Pseudonym::<Ristretto255>::random(rng);
/// let attribute = Attribute::<Ristretto255>::random(rng);
///
/// // The data's type selects the half of the bundle: pseudonym key here.
/// let encrypted_pseudonym = encrypt(&pseudonym, &keys.pseudonym.public, rng);
/// // Or from the session's public keys, which selects the half itself.
/// let encrypted_pseudonym = encrypt(&pseudonym, &keys.public(), rng);
/// let encrypted_attribute = encrypt(&attribute, &keys.public(), rng);
/// ```
pub fn encrypt<G: Group, M, R>(
    message: &M,
    key: &impl KeyProvider<M::PublicKeyType>,
    rng: &mut R,
) -> M::EncryptedType
where
    M: Encryptable<Group = G>,
    R: Rng + CryptoRng,
{
    message.encrypt(&key.get_key(), rng)
}

/// Polymorphic decrypt function that works for any encrypted type.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
///
/// # Examples
/// ```
/// # use libpep::client::{decrypt, encrypt};
/// # use libpep::contexts::EncryptionContext;
/// # use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
/// # use libpep::group::Ristretto255;
/// # use libpep::factors::RekeyingSecret;
/// # use libpep::keys::{make_global_keys, make_session_keys};
/// # use libpep::ciphersuite::Ristretto255Sha512;
/// # let rng = &mut rand::rng();
/// # let (_global_public, global_secret) = make_global_keys(rng);
/// # let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
/// # let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
/// let pseudonym = Pseudonym::<Ristretto255>::random(rng);
/// let encrypted = encrypt(&pseudonym, &keys.public(), rng);
/// assert_eq!(decrypt(&encrypted, &keys), Some(pseudonym));
/// ```
#[cfg(feature = "elgamal3")]
pub fn decrypt<G: Group, E>(
    encrypted: &E,
    key: &impl KeyProvider<E::SecretKeyType>,
) -> Option<E::UnencryptedType>
where
    E: Encrypted<Group = G>,
{
    encrypted.decrypt(&key.get_key())
}

/// Polymorphic decrypt function that works for any encrypted type.
///
/// # Examples
/// ```
/// # use libpep::client::{decrypt, encrypt};
/// # use libpep::contexts::EncryptionContext;
/// # use libpep::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
/// # use libpep::group::Ristretto255;
/// # use libpep::factors::RekeyingSecret;
/// # use libpep::keys::{make_global_keys, make_session_keys};
/// # use libpep::ciphersuite::Ristretto255Sha512;
/// # let rng = &mut rand::rng();
/// # let (_global_public, global_secret) = make_global_keys(rng);
/// # let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
/// # let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
/// let pseudonym = Pseudonym::<Ristretto255>::random(rng);
/// let encrypted = encrypt(&pseudonym, &keys.public(), rng);
/// assert_eq!(decrypt(&encrypted, &keys), pseudonym);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt<G: Group, E>(
    encrypted: &E,
    key: &impl KeyProvider<E::SecretKeyType>,
) -> E::UnencryptedType
where
    E: Encrypted<Group = G>,
{
    encrypted.decrypt(&key.get_key())
}

/// Polymorphic encrypt_global function for offline encryption.
///
/// # Examples
/// ```
/// # use libpep::client::encrypt_global;
/// # use libpep::data::simple::{ElGamalEncryptable, Pseudonym};
/// # use libpep::group::Ristretto255;
/// # use libpep::keys::make_global_keys;
/// # let rng = &mut rand::rng();
/// # let (global_public, _global_secret) = make_global_keys(rng);
/// let pseudonym = Pseudonym::<Ristretto255>::random(rng);
/// let encrypted = encrypt_global(&pseudonym, &global_public, rng);
/// ```
#[cfg(feature = "offline")]
pub fn encrypt_global<G: Group, M, R>(
    message: &M,
    key: &impl KeyProvider<M::GlobalPublicKeyType>,
    rng: &mut R,
) -> M::EncryptedType
where
    M: Encryptable<Group = G>,
    R: Rng + CryptoRng,
{
    message.encrypt_global(&key.get_key(), rng)
}

/// Polymorphic decrypt_global function for offline decryption.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
#[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_global<G: Group, E>(
    encrypted: &E,
    key: &impl KeyProvider<E::GlobalSecretKeyType>,
) -> Option<E::UnencryptedType>
where
    E: Encrypted<Group = G>,
{
    encrypted.decrypt_global(&key.get_key())
}

/// Polymorphic decrypt_global function for offline decryption.
#[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_global<G: Group, E>(
    encrypted: &E,
    key: &impl KeyProvider<E::GlobalSecretKeyType>,
) -> E::UnencryptedType
where
    E: Encrypted<Group = G>,
{
    encrypted.decrypt_global(&key.get_key())
}
