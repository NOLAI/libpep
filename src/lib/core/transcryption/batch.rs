//! Batch operations for pseudonymization, rekeying, and transcryption.
//!
//! These operations process multiple encrypted items at once and shuffle them
//! to prevent linking.

use super::ops::{pseudonymize, rekey};
use crate::core::data::*;
use crate::core::transcryption::contexts::*;
use crate::core::transcryption::{transcrypt_attribute, transcrypt_pseudonym};
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

/// Trait for types that can be transcrypted using TranscryptionInfo.
/// This trait is implemented separately for pseudonyms, attributes and encrypted_data to provide
/// type-specific transcryption behavior without runtime dispatch.
pub trait BatchTranscryptable<R: RngCore + CryptoRng> {
    /// Apply the transcryption operation specific to this type.
    fn transcrypt_batch_impl(
        encrypted: Self,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Self, String>
    where
        Self: Sized;
}

impl<R: RngCore + CryptoRng> BatchTranscryptable<R> for Vec<EncryptedPseudonym> {
    #[inline]
    fn transcrypt_batch_impl(
        encrypted: Self,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Self, String> {
        let mut shuffled = encrypted.clone();
        shuffle(&mut shuffled, rng); // Shuffle the order to avoid linking
        let result = shuffled
            .iter()
            .map(|x| transcrypt_pseudonym(x, transcryption_info))
            .collect();

        Ok(result)
    }
}

impl<R: RngCore + CryptoRng> BatchTranscryptable<R> for Vec<EncryptedAttribute> {
    #[inline]
    fn transcrypt_batch_impl(
        encrypted: Self,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Self, String> {
        let mut shuffled = encrypted.clone();
        shuffle(&mut shuffled, rng); // Shuffle the order to avoid linking
        let result = shuffled
            .iter()
            .map(|x| transcrypt_attribute(x, transcryption_info))
            .collect();

        Ok(result)
    }
}
impl<R: RngCore + CryptoRng> BatchTranscryptable<R> for Vec<EncryptedData> {
    #[inline]
    fn transcrypt_batch_impl(
        encrypted: Self,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Self, String> {
        let mut encrypted = encrypted.clone();

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
}

/// Transcrypt an encrypted message from one pseudonymization and encryption context to another,
/// using [`TranscryptionInfo`].
///
/// When an [`EncryptedPseudonym`] is transcrypted, the result is a pseudonymized pseudonym
/// (applying both reshuffle and rekey operations).
/// When an [`EncryptedAttribute`] is transcrypted, the result is a rekeyed attribute
/// (applying only the rekey operation, as attributes cannot be reshuffled).
pub fn transcrypt_batch<E: BatchTranscryptable<R>, R: RngCore + CryptoRng>(
    encrypted: E,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Result<E, String> {
    E::transcrypt_batch_impl(encrypted, transcryption_info, rng)
}
