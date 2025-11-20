//! Batch operations for long (multi-block) data types.
//!
//! These operations process multiple long encrypted items at once and shuffle them
//! to prevent linking.

use super::core::{LongEncryptedAttribute, LongEncryptedPseudonym};
use super::ops::{pseudonymize_long, rekey_long_attribute, rekey_long_pseudonym};
use crate::high_level::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

/// A pair of long encrypted pseudonyms and attributes that relate to the same entity, used for batch transcryption.
pub type LongEncryptedData = (Vec<LongEncryptedPseudonym>, Vec<LongEncryptedAttribute>);

/// Batch pseudonymization of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
pub fn pseudonymize_long_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [LongEncryptedPseudonym],
    pseudonymization_info: &PseudonymizationInfo,
    rng: &mut R,
) -> Box<[LongEncryptedPseudonym]> {
    encrypted.shuffle(rng);
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
    encrypted.shuffle(rng);
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
    encrypted.shuffle(rng);
    encrypted
        .iter()
        .map(|x| rekey_long_attribute(x, rekey_info))
        .collect()
}

/// Batch transcryption of long encrypted data.
/// The order of the pairs (entities) is randomly shuffled to avoid linking them, but the internal
/// order of pseudonyms and attributes for the same entity is preserved.
pub fn transcrypt_long_batch<R: RngCore + CryptoRng>(
    encrypted: &mut Box<[LongEncryptedData]>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Box<[LongEncryptedData]> {
    encrypted.shuffle(rng);
    encrypted
        .iter_mut()
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
        .collect()
}
