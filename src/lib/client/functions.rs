//! Polymorphic encryption and decryption helper functions for client operations.

use crate::data::traits::{Encryptable, Encrypted};
use rand_core::{CryptoRng, RngCore};

/// Polymorphic encrypt function that works for any encryptable type.
///
/// # Examples
/// ```rust,ignore
/// let encrypted_pseudonym = encrypt(&pseudonym, &pseudonym_key, &mut rng);
/// let encrypted_attribute = encrypt(&attribute, &attribute_key, &mut rng);
/// let encrypted_long = encrypt(&long_pseudonym, &pseudonym_key, &mut rng);
/// ```
pub fn encrypt<M, R>(message: &M, public_key: &M::PublicKeyType, rng: &mut R) -> M::EncryptedType
where
    M: Encryptable,
    R: RngCore + CryptoRng,
{
    message.encrypt(public_key, rng)
}

/// Polymorphic decrypt function that works for any encrypted type.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
///
/// # Examples
/// ```rust,ignore
/// let pseudonym = decrypt(&encrypted_pseudonym, &pseudonym_key);
/// let attribute = decrypt(&encrypted_attribute, &attribute_key);
/// ```
#[cfg(feature = "elgamal3")]
pub fn decrypt<E>(encrypted: &E, secret_key: &E::SecretKeyType) -> Option<E::UnencryptedType>
where
    E: Encrypted,
{
    encrypted.decrypt(secret_key)
}

/// Polymorphic decrypt function that works for any encrypted type.
///
/// # Examples
/// ```rust,ignore
/// let pseudonym = decrypt(&encrypted_pseudonym, &pseudonym_key);
/// let attribute = decrypt(&encrypted_attribute, &attribute_key);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt<E>(encrypted: &E, secret_key: &E::SecretKeyType) -> E::UnencryptedType
where
    E: Encrypted,
{
    encrypted.decrypt(secret_key)
}

/// Polymorphic encrypt_global function for offline encryption.
///
/// # Examples
/// ```rust,ignore
/// let encrypted = encrypt_global(&pseudonym, &global_key, &mut rng);
/// ```
#[cfg(feature = "offline")]
pub fn encrypt_global<M, R>(
    message: &M,
    public_key: &M::GlobalPublicKeyType,
    rng: &mut R,
) -> M::EncryptedType
where
    M: Encryptable,
    R: RngCore + CryptoRng,
{
    message.encrypt_global(public_key, rng)
}

/// Polymorphic decrypt_global function for offline decryption.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
#[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_global<E>(
    encrypted: &E,
    secret_key: &E::GlobalSecretKeyType,
) -> Option<E::UnencryptedType>
where
    E: Encrypted,
{
    encrypted.decrypt_global(secret_key)
}

/// Polymorphic decrypt_global function for offline decryption.
#[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_global<E>(encrypted: &E, secret_key: &E::GlobalSecretKeyType) -> E::UnencryptedType
where
    E: Encrypted,
{
    encrypted.decrypt_global(secret_key)
}
