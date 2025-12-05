//! Batch operations for pseudonymization, rekeying, and transcryption.
//!
//! These operations process multiple encrypted items at once and shuffle them
//! to prevent linking.

use super::ops::{pseudonymize, rekey};
use crate::core::data::*;
use crate::core::transcryption::contexts::*;
use rand_core::{CryptoRng, RngCore};

/// Fisher-Yates shuffle using rand_core
fn shuffle<T, R: RngCore>(slice: &mut [T], rng: &mut R) {
    for i in (1..slice.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        slice.swap(i, j);
    }
}

/// Batch pseudonymization of a slice of [`EncryptedPseudonym`]s, using [`PseudonymizationInfo`].
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
pub fn pseudonymize_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [EncryptedPseudonym],
    pseudonymization_info: &PseudonymizationInfo,
    rng: &mut R,
) -> Box<[EncryptedPseudonym]> {
    shuffle(encrypted, rng); // Shuffle the order to avoid linking
    encrypted
        .iter()
        .map(|x| pseudonymize(x, pseudonymization_info))
        .collect()
}

/// Batch rekeying of a slice of [`EncryptedAttribute`]s, using [`AttributeRekeyInfo`].
/// The order of the attributes is randomly shuffled to avoid linking them.
pub fn rekey_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [EncryptedAttribute],
    rekey_info: &AttributeRekeyInfo,
    rng: &mut R,
) -> Box<[EncryptedAttribute]> {
    shuffle(encrypted, rng); // Shuffle the order to avoid linking
    encrypted.iter().map(|x| rekey(x, rekey_info)).collect()
}

/// A pair of encrypted pseudonyms and attributes that relate to the same entity, used for batch transcryption.
pub type EncryptedData = (Vec<EncryptedPseudonym>, Vec<EncryptedAttribute>);

/// Batch transcryption of a slice of [`EncryptedData`]s, using [`TranscryptionInfo`].
/// The order of the pairs (entities) is randomly shuffled to avoid linking them, but the internal
/// order of pseudonyms and attributes for the same entity is preserved.
///
/// # Errors
///
/// Returns an error if the encrypted data do not all have the same structure (same number of pseudonyms and attributes).
pub fn transcrypt_batch<R: RngCore + CryptoRng>(
    mut encrypted: Vec<EncryptedData>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Result<Vec<EncryptedData>, String> {
    // Check that all EncryptedData have the same structure
    if let Some((enc_pseudonyms, enc_attributes)) = encrypted.first() {
        let expected_pseudonym_len = enc_pseudonyms.len();
        let expected_attribute_len = enc_attributes.len();

        for (index, (pseudonyms, attributes)) in encrypted.iter().enumerate() {
            if pseudonyms.len() != expected_pseudonym_len {
                return Err(format!(
                    "All EncryptedData must have the same structure. Entry at index {} has {} pseudonyms, expected {}.",
                    index, pseudonyms.len(), expected_pseudonym_len
                ));
            }
            if attributes.len() != expected_attribute_len {
                return Err(format!(
                    "All EncryptedData must have the same structure. Entry at index {} has {} attributes, expected {}.",
                    index, attributes.len(), expected_attribute_len
                ));
            }
        }
    }

    shuffle(&mut encrypted, rng); // Shuffle the order to avoid linking
    let result = encrypted
        .iter()
        .map(|(pseudonyms, attributes)| {
            let pseudonyms = pseudonyms
                .iter()
                .map(|x| pseudonymize(x, &transcryption_info.pseudonym))
                .collect();
            let attributes = attributes
                .iter()
                .map(|x| rekey(x, &transcryption_info.attribute))
                .collect();
            (pseudonyms, attributes)
        })
        .collect();
    Ok(result)
}
