//! Batch operations for encryption and decryption.

use crate::data::batch::EncryptedBatch;
use crate::data::traits::{Encryptable, Encrypted, HasStructure};
use crate::errors::BatchError;
use crate::keys::KeyProvider;
use rand_core::{CryptoRng, Rng};

/// Polymorphic batch encryption.
///
/// Encrypts a slice of unencrypted messages with a session public key and
/// returns an [`EncryptedBatch`] that carries the public key alongside the
/// items (under `elgamal2`) so downstream batch operations need no extra
/// arguments.
pub fn encrypt_batch<M, R>(
    messages: &[M],
    key: &impl KeyProvider<M::PublicKeyType>,
    rng: &mut R,
) -> Result<EncryptedBatch<M::EncryptedType>, BatchError>
where
    M: Encryptable + Clone,
    M::PublicKeyType: Clone,
    M::EncryptedType: HasStructure,
    R: Rng + CryptoRng,
{
    let preprocessed = M::preprocess_for_batch(messages)?;
    let key = key.get_key();
    let items: Vec<M::EncryptedType> = preprocessed.iter().map(|x| x.encrypt(&key, rng)).collect();
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    {
        EncryptedBatch::new(items, key)
    }
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    {
        EncryptedBatch::new(items)
    }
}

#[cfg(feature = "insecure")]
pub fn encrypt_batch_raw<M, R>(
    messages: &[M],
    key: &impl KeyProvider<M::PublicKeyType>,
    rng: &mut R,
) -> Result<Vec<M::EncryptedType>, BatchError>
where
    M: Encryptable,
    R: Rng + CryptoRng,
{
    let key = key.get_key();
    Ok(messages.iter().map(|x| x.encrypt(&key, rng)).collect())
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
    key: &impl KeyProvider<M::GlobalPublicKeyType>,
    rng: &mut R,
) -> Result<Vec<M::EncryptedType>, BatchError>
where
    M: Encryptable,
    R: Rng + CryptoRng,
{
    let key = key.get_key();
    Ok(messages
        .iter()
        .map(|x| x.encrypt_global(&key, rng))
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
    key: &impl KeyProvider<E::SecretKeyType>,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    let key = key.get_key();
    encrypted
        .iter()
        .enumerate()
        .map(|(index, x)| {
            x.decrypt(&key)
                .ok_or(BatchError::DecryptionFailed { index })
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
    key: &impl KeyProvider<E::SecretKeyType>,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    let key = key.get_key();
    Ok(encrypted.iter().map(|x| x.decrypt(&key)).collect())
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
    key: &impl KeyProvider<E::GlobalSecretKeyType>,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    let key = key.get_key();
    encrypted
        .iter()
        .enumerate()
        .map(|(index, x)| {
            x.decrypt_global(&key)
                .ok_or(BatchError::DecryptionFailed { index })
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
    key: &impl KeyProvider<E::GlobalSecretKeyType>,
) -> Result<Vec<E::UnencryptedType>, BatchError>
where
    E: Encrypted,
{
    let key = key.get_key();
    Ok(encrypted.iter().map(|x| x.decrypt_global(&key)).collect())
}
