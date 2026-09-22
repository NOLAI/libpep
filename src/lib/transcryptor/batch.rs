//! Batch operations for pseudonymization, rekeying, and transcryption with shuffling.

#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{HasStructure, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::types::generic::{PseudonymizationInfo, TranscryptionInfo};
use rand_core::{CryptoRng, Rng};

use crate::errors::BatchError;

/// Uniformly random index in `0..n` (n > 0), by rejection sampling on the random 64-bit output so
/// that the result is unbiased (a plain `% n` is biased for n not dividing 2^64).
fn random_index<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> usize {
    let n = n as u64;
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = rng.next_u64();
        if v < zone {
            return (v % n) as usize;
        }
    }
}

/// Fisher-Yates shuffle with unbiased index sampling.
fn shuffle<T, R: Rng + CryptoRng>(slice: &mut [T], rng: &mut R) {
    for i in (1..slice.len()).rev() {
        let j = random_index(i + 1, rng);
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
#[cfg(feature = "elgamal3")]
pub fn pseudonymize_batch<E, R>(
    encrypted: &mut [E],
    info: &PseudonymizationInfo<E::Group>,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.pseudonymize(info, rng))
        .collect())
}

#[cfg(not(feature = "elgamal3"))]
pub fn pseudonymize_batch<E, R>(
    encrypted: &mut [E],
    info: &PseudonymizationInfo<E::Group>,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.pseudonymize(info, public_key, rng))
        .collect())
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
#[cfg(feature = "elgamal3")]
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
    Ok(encrypted.iter().map(|x| x.rekey(info, rng)).collect())
}

#[cfg(not(feature = "elgamal3"))]
pub fn rekey_batch<E, R>(
    encrypted: &mut [E],
    info: &E::RekeyInfo,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Rekeyable + HasStructure + Clone,
    E::RekeyInfo: Copy,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.rekey(info, public_key, rng))
        .collect())
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
#[cfg(feature = "elgamal3")]
pub fn transcrypt_batch<E, R>(
    encrypted: &mut [E],
    info: &TranscryptionInfo<E::Group>,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Transcryptable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|x| x.transcrypt(info, rng)).collect())
}

#[cfg(not(feature = "elgamal3"))]
pub fn transcrypt_batch<E, R>(
    encrypted: &mut [E],
    info: &TranscryptionInfo<E::Group>,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Transcryptable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.transcrypt(info, public_key, rng))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_index_stays_in_range() {
        let rng = &mut rand::rng();
        for n in [1usize, 2, 3, 7, 100, 1000] {
            for _ in 0..1000 {
                assert!(random_index(n, rng) < n);
            }
        }
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let rng = &mut rand::rng();
        let original: Vec<u32> = (0..50).collect();
        let mut shuffled = original.clone();
        shuffle(&mut shuffled, rng);
        let mut sorted = shuffled.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, original);
        assert_ne!(shuffled, original);
    }
}
