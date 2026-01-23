//! Polymorphic helper functions for encryption, decryption, and transcryption operations.
//!
//! These functions work with any type implementing the corresponding traits from [`crate::core::data::traits`].

use crate::core::data::traits::{
    Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable,
};
use crate::core::factors::TranscryptionInfo;
use crate::core::factors::{PseudonymizationInfo, RerandomizeFactor};
use rand_core::{CryptoRng, RngCore};

// Encryption and decryption functions

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

// Rerandomization functions

/// Rerandomize an encrypted message, creating a binary unlinkable copy of the same message.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize(&encrypted_pseudonym, &mut rng);
/// ```
#[cfg(feature = "elgamal3")]
pub fn rerandomize<R, E>(encrypted: &E, rng: &mut R) -> E
where
    E: Encrypted,
    R: RngCore + CryptoRng,
{
    encrypted.rerandomize(rng)
}

/// Rerandomize an encrypted message, creating a binary unlinkable copy of the same message.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize(&encrypted_pseudonym, &public_key, &mut rng);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize<R, E>(
    encrypted: &E,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> E
where
    E: Encrypted,
    R: RngCore + CryptoRng,
{
    encrypted.rerandomize(public_key, rng)
}

/// Rerandomize an encrypted message using a known rerandomization factor.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize_known(&encrypted_pseudonym, &factor);
/// ```
#[cfg(feature = "elgamal3")]
pub fn rerandomize_known<E>(encrypted: &E, factor: &RerandomizeFactor) -> E
where
    E: Encrypted,
{
    encrypted.rerandomize_known(factor)
}

/// Rerandomize an encrypted message using a known rerandomization factor.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize_known(&encrypted_pseudonym, &public_key, &factor);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_known<E>(
    encrypted: &E,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    factor: &RerandomizeFactor,
) -> E
where
    E: Encrypted,
{
    encrypted.rerandomize_known(public_key, factor)
}

// Transcryption functions

/// Polymorphic pseudonymize function for encrypted pseudonyms.
///
/// # Examples
/// ```rust,ignore
/// let pseudonymized = pseudonymize(&encrypted_pseudonym, &pseudonymization_info);
/// ```
pub fn pseudonymize<E>(encrypted: &E, info: &PseudonymizationInfo) -> E
where
    E: Pseudonymizable,
{
    encrypted.pseudonymize(info)
}

/// Polymorphic rekey function for any encrypted type.
///
/// # Examples
/// ```rust,ignore
/// let rekeyed_pseudonym = rekey(&encrypted_pseudonym, &pseudonym_rekey_info);
/// let rekeyed_attribute = rekey(&encrypted_attribute, &attribute_rekey_info);
/// ```
pub fn rekey<E>(encrypted: &E, info: &E::RekeyInfo) -> E
where
    E: Rekeyable,
{
    encrypted.rekey(info)
}

/// Polymorphic transcrypt function for any encrypted type.
///
/// # Examples
/// ```rust,ignore
/// let transcrypted_pseudonym = transcrypt(&encrypted_pseudonym, &transcryption_info);
/// let transcrypted_attribute = transcrypt(&encrypted_attribute, &transcryption_info);
/// let transcrypted_json = transcrypt(&encrypted_json_value, &transcryption_info);
/// ```
pub fn transcrypt<E>(encrypted: &E, info: &TranscryptionInfo) -> E
where
    E: Transcryptable,
{
    encrypted.transcrypt(info)
}
