//! Batch operations for encryption and decryption.

use crate::data::batch::EncryptedBatch;
use crate::data::traits::{Encryptable, Encrypted, HasStructure};
use crate::errors::BatchError;
use crate::keys::KeyProvider;
use rand_core::{CryptoRng, Rng};

/// Encrypt a slice of values into an [`EncryptedBatch`].
///
/// The values are first brought to one structure where their type requires it (JSON values
/// are padded to a unified structure), so that the batch can be shuffled without linking
/// items through their shape. With the `batch-pk` feature the batch carries the public key.
///
/// # Errors
///
/// Returns an error if the values cannot be brought to one structure.
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

/// Encrypt a slice of values one by one, without bringing them to one structure.
///
/// The result is not an [`EncryptedBatch`]: values of different structure must not be
/// shuffled together, as their shapes would link them.
#[cfg(feature = "insecure")]
pub fn encrypt_batch_raw<M, R>(
    messages: &[M],
    key: &impl KeyProvider<M::PublicKeyType>,
    rng: &mut R,
) -> Vec<M::EncryptedType>
where
    M: Encryptable,
    R: Rng + CryptoRng,
{
    let key = key.get_key();
    messages.iter().map(|x| x.encrypt(&key, rng)).collect()
}

/// Encrypt a slice of values one by one towards a global public key.
///
/// The result is not an [`EncryptedBatch`]: values encrypted towards the global keys are not
/// in a session yet, and become a batch once rekeyed into one.
#[cfg(feature = "offline")]
pub fn encrypt_global_batch<M, R>(
    messages: &[M],
    key: &impl KeyProvider<M::GlobalPublicKeyType>,
    rng: &mut R,
) -> Vec<M::EncryptedType>
where
    M: Encryptable,
    R: Rng + CryptoRng,
{
    let key = key.get_key();
    messages
        .iter()
        .map(|x| x.encrypt_global(&key, rng))
        .collect()
}

/// Decrypt a slice of values with a session secret key.
///
/// # Errors
///
/// Returns an error if any decryption fails; only possible with the `elgamal3` feature.
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

/// Decrypt a slice of values with a session secret key.
///
/// # Errors
///
/// Never fails without the `elgamal3` feature; the result type is the same in both modes.
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

/// Decrypt a slice of values with a global secret key.
///
/// # Errors
///
/// Returns an error if any decryption fails; only possible with the `elgamal3` feature.
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

/// Decrypt a slice of values with a global secret key.
///
/// # Errors
///
/// Never fails without the `elgamal3` feature; the result type is the same in both modes.
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
