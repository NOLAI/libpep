//! Batch operations for pseudonymization, rekeying, and transcryption with shuffling.

use crate::data::traits::{HasStructure, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::TranscryptionInfo;
use rand_core::{CryptoRng, Rng};

use crate::errors::BatchError;

/// Fisher-Yates shuffle using rand_core
fn shuffle<T, R: Rng + CryptoRng>(slice: &mut [T], rng: &mut R) {
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
    info: &crate::factors::PseudonymizationInfo,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: Rng + CryptoRng,
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
    R: Rng + CryptoRng,
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
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|x| x.transcrypt(info)).collect())
}
