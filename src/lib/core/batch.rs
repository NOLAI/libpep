//! Batch operations for encryption, decryption, pseudonymization, rekeying, and transcryption.
//!
//! These operations process multiple items at once and shuffle them
//! to prevent linking.

use crate::core::contexts::TranscryptionInfo;
use crate::core::data::traits::{
    Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

/// Error type for batch operation failures.
#[derive(Debug, Error)]
pub enum BatchError {
    /// Items in the batch have inconsistent structures.
    ///
    /// All items in a batch must have the same structure to prevent linkability.
    /// If items had different structures (e.g., different numbers of blocks in long values,
    /// different JSON shapes, or different numbers of pseudonyms/attributes in records),
    /// an attacker could potentially link items across batches based on their structure,
    /// defeating the privacy protection provided by shuffling.
    #[error("Inconsistent structure in batch. Entry at index {index} has structure {actual_structure}, expected {expected_structure}.")]
    InconsistentStructure {
        index: usize,
        expected_structure: String,
        actual_structure: String,
    },
}

/// A trait for encrypted types that have a structure that must be validated during batch operations.
///
/// Types implementing this trait require all items in a batch to have the same structure
/// (e.g., same number of pseudonyms/attributes in records, same JSON shape, etc.).
pub trait HasStructure {
    /// The type representing the structure of this encrypted value.
    type Structure: PartialEq + std::fmt::Debug;

    /// Get the structure of this encrypted value.
    fn structure(&self) -> Self::Structure;
}

/// Fisher-Yates shuffle using rand_core
fn shuffle<T, R: RngCore>(slice: &mut [T], rng: &mut R) {
    for i in (1..slice.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        slice.swap(i, j);
    }
}

/// Validates that all items in a slice have the same structure.
///
/// # Errors
///
/// Returns an error if items have different structures.
fn validate_structure<E: HasStructure>(encrypted: &[E]) -> Result<(), BatchError> {
    if let Some(first) = encrypted.first() {
        let expected_structure = first.structure();
        for (index, item) in encrypted.iter().enumerate().skip(1) {
            let item_structure = item.structure();
            if item_structure != expected_structure {
                return Err(BatchError::InconsistentStructure {
                    index,
                    expected_structure: format!("{:?}", expected_structure),
                    actual_structure: format!("{:?}", item_structure),
                });
            }
        }
    }
    Ok(())
}

/// Polymorphic batch pseudonymization with structure validation and shuffling.
///
/// Pseudonymizes a slice of encrypted pseudonyms and shuffles their order to prevent linking.
/// For types implementing `HasStructure`, validates that all items have the same structure.
///
/// # Errors
///
/// Returns an error if the encrypted values do not all have the same structure
/// (for types implementing `HasStructure`).
///
/// # Examples
/// ```rust,ignore
/// let pseudonymized = pseudonymize_batch(&mut encrypted_pseudonyms, &info, &mut rng)?;
/// ```
pub fn pseudonymize_batch<E, R>(
    encrypted: &mut [E],
    info: &crate::core::contexts::PseudonymizationInfo,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: RngCore + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|x| x.pseudonymize(info)).collect())
}

/// Polymorphic batch rekeying with structure validation and shuffling.
///
/// Rekeys a slice of encrypted values and shuffles their order to prevent linking.
/// For types implementing `HasStructure`, validates that all items have the same structure.
///
/// # Errors
///
/// Returns an error if the encrypted values do not all have the same structure
/// (for types implementing `HasStructure`).
///
/// # Examples
/// ```rust,ignore
/// let rekeyed = rekey_batch(&mut encrypted_attributes, &info, &mut rng)?;
/// ```
pub fn rekey_batch<E, R>(
    encrypted: &mut [E],
    info: &E::RekeyInfo,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Rekeyable + HasStructure + Clone,
    E::RekeyInfo: Copy,
    R: RngCore + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|x| x.rekey(info)).collect())
}

/// Polymorphic batch transcryption with structure validation and shuffling.
///
/// Transcrypts a slice of encrypted values and shuffles their order to prevent linking.
/// For types implementing `HasStructure`, validates that all items have the same structure.
///
/// # Errors
///
/// Returns an error if the encrypted values do not all have the same structure
/// (for types implementing `HasStructure`).
///
/// # Examples
/// ```rust,ignore
/// let transcrypted = transcrypt_batch(&mut encrypted_records, &info, &mut rng)?;
/// ```
pub fn transcrypt_batch<E, R>(
    encrypted: &mut [E],
    info: &TranscryptionInfo,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Transcryptable + HasStructure + Clone,
    R: RngCore + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|x| x.transcrypt(info)).collect())
}

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
