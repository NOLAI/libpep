//! Batch operations for long (multi-block) data types.
//!
//! These operations process multiple long encrypted items at once and shuffle them
//! to prevent linking.

use super::data::{LongEncryptedAttribute, LongEncryptedPseudonym};
use super::transcryption::{pseudonymize_long, rekey_long_attribute, rekey_long_pseudonym};
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use rand_core::{CryptoRng, RngCore};

/// Fisher-Yates shuffle using rand_core
fn shuffle<T, R: RngCore>(slice: &mut [T], rng: &mut R) {
    for i in (1..slice.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        slice.swap(i, j);
    }
}

/// A pair of long encrypted pseudonyms and attributes that relate to the same entity, used for batch transcryption.
pub type LongEncryptedData = (Vec<LongEncryptedPseudonym>, Vec<LongEncryptedAttribute>);

/// Batch pseudonymization of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
pub fn pseudonymize_long_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [LongEncryptedPseudonym],
    pseudonymization_info: &PseudonymizationInfo,
    rng: &mut R,
) -> Box<[LongEncryptedPseudonym]> {
    shuffle(encrypted, rng);
    encrypted
        .iter()
        .map(|x| pseudonymize_long(x, pseudonymization_info))
        .collect()
}

/// Batch rekeying of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
pub fn rekey_long_pseudonym_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [LongEncryptedPseudonym],
    rekey_info: &PseudonymRekeyInfo,
    rng: &mut R,
) -> Box<[LongEncryptedPseudonym]> {
    shuffle(encrypted, rng);
    encrypted
        .iter()
        .map(|x| rekey_long_pseudonym(x, rekey_info))
        .collect()
}

/// Batch rekeying of long encrypted attributes.
/// The order of the attributes is randomly shuffled to avoid linking them.
pub fn rekey_long_attribute_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [LongEncryptedAttribute],
    rekey_info: &AttributeRekeyInfo,
    rng: &mut R,
) -> Box<[LongEncryptedAttribute]> {
    shuffle(encrypted, rng);
    encrypted
        .iter()
        .map(|x| rekey_long_attribute(x, rekey_info))
        .collect()
}

/// Batch transcryption of long encrypted data.
/// The order of the pairs (entities) is randomly shuffled to avoid linking them, but the internal
/// order of pseudonyms and attributes for the same entity is preserved.
///
/// # Errors
///
/// Returns an error if the encrypted data do not all have the same structure (same number of pseudonyms and attributes).
pub fn transcrypt_long_batch<R: RngCore + CryptoRng>(
    mut encrypted: Vec<LongEncryptedData>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Result<Vec<LongEncryptedData>, String> {
    // Check that all LongEncryptedData have the same structure
    if let Some((enc_pseudonyms, enc_attributes)) = encrypted.first() {
        let expected_pseudonym_len = enc_pseudonyms.len();
        let expected_attribute_len = enc_attributes.len();

        for (index, (pseudonyms, attributes)) in encrypted.iter().enumerate() {
            if pseudonyms.len() != expected_pseudonym_len {
                return Err(format!(
                    "All LongEncryptedData must have the same structure. Entry at index {} has {} pseudonyms, expected {}.",
                    index, pseudonyms.len(), expected_pseudonym_len
                ));
            }
            if attributes.len() != expected_attribute_len {
                return Err(format!(
                    "All LongEncryptedData must have the same structure. Entry at index {} has {} attributes, expected {}.",
                    index, attributes.len(), expected_attribute_len
                ));
            }
        }
    }

    shuffle(&mut encrypted, rng);
    let result = encrypted
        .iter()
        .map(|(pseudonyms, attributes)| {
            let pseudonyms = pseudonyms
                .iter()
                .map(|x| pseudonymize_long(x, &transcryption_info.pseudonym))
                .collect();
            let attributes = attributes
                .iter()
                .map(|x| rekey_long_attribute(x, &transcryption_info.attribute))
                .collect();
            (pseudonyms, attributes)
        })
        .collect();
    Ok(result)
}
