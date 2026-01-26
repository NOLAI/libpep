//! Batch operations for encryption and decryption.

use crate::data::traits::{Encryptable, Encrypted};
use crate::transcryptor::batch::BatchError;
use rand_core::{CryptoRng, RngCore};

/// Polymorphic batch encryption.
///
/// Encrypts a slice of unencrypted messages with a session public key.
///
/// # Examples
/// ```rust,ignore
/// let encrypted = encrypt_batch(&messages, &public_key, &mut rng)?;
/// ```
pub fn encrypt_batch<M, R>(
    messages: &[M],
    public_key: &M::PublicKeyType,
    rng: &mut R,
) -> Result<Vec<M::EncryptedType>, BatchError>
where
    M: Encryptable,
    R: RngCore + CryptoRng,
{
    Ok(messages
        .iter()
        .map(|x| x.encrypt(public_key, rng))
        .collect())
}

/// Polymorphic batch encryption with global public key.
///
/// Encrypts a slice of unencrypted messages with a global public key.
///
/// # Examples
/// ```rust,ignore
/// let encrypted = encrypt_global_batch(&messages, &global_public_key, &mut rng)?;
/// ```
#[cfg(feature = "offline")]
pub fn encrypt_global_batch<M, R>(
    messages: &[M],
    public_key: &M::GlobalPublicKeyType,
    rng: &mut R,
) -> Result<Vec<M::EncryptedType>, BatchError>
where
    M: Encryptable,
    R: RngCore + CryptoRng,
{
    Ok(messages
        .iter()
        .map(|x| x.encrypt_global(public_key, rng))
        .collect())
}

/// Polymorphic batch decryption.
///
/// Decrypts a slice of encrypted messages with a session secret key.
/// With the `elgamal3` feature, returns an error if any decryption fails.
///
/// # Examples
/// ```rust,ignore
/// let decrypted = decrypt_batch(&encrypted, &secret_key)?;
/// ```
#[cfg(feature = "elgamal3")]
pub fn decrypt_batch<E>(
    encrypted: &[E],
    secret_key: &E::SecretKeyType,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    encrypted
        .iter()
        .map(|x| {
            x.decrypt(secret_key)
                .ok_or_else(|| BatchError::InconsistentStructure {
                    index: 0,
                    expected_structure: "valid decryption".to_string(),
                    actual_structure: "decryption failed".to_string(),
                })
        })
        .collect()
}

/// Polymorphic batch decryption.
///
/// Decrypts a slice of encrypted messages with a session secret key.
///
/// # Examples
/// ```rust,ignore
/// let decrypted = decrypt_batch(&encrypted, &secret_key)?;
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt_batch<E>(
    encrypted: &[E],
    secret_key: &E::SecretKeyType,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    Ok(encrypted.iter().map(|x| x.decrypt(secret_key)).collect())
}

/// Polymorphic batch decryption with global secret key.
///
/// Decrypts a slice of encrypted messages with a global secret key.
/// With the `elgamal3` feature, returns an error if any decryption fails.
///
/// # Examples
/// ```rust,ignore
/// let decrypted = decrypt_global_batch(&encrypted, &global_secret_key)?;
/// ```
#[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_global_batch<E>(
    encrypted: &[E],
    secret_key: &E::GlobalSecretKeyType,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    encrypted
        .iter()
        .map(|x| {
            x.decrypt_global(secret_key)
                .ok_or_else(|| BatchError::InconsistentStructure {
                    index: 0,
                    expected_structure: "valid decryption".to_string(),
                    actual_structure: "decryption failed".to_string(),
                })
        })
        .collect()
}

/// Polymorphic batch decryption with global secret key.
///
/// Decrypts a slice of encrypted messages with a global secret key.
///
/// # Examples
/// ```rust,ignore
/// let decrypted = decrypt_global_batch(&encrypted, &global_secret_key)?;
/// ```
#[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_global_batch<E>(
    encrypted: &[E],
    secret_key: &E::GlobalSecretKeyType,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    Ok(encrypted
        .iter()
        .map(|x| x.decrypt_global(secret_key))
        .collect())
}
