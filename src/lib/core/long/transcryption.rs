//! Operations for long (multi-block) data types including encryption, decryption,
//! rerandomization, rekeying, pseudonymization, and transcryption.

use super::data::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(all(feature = "offline", feature = "insecure"))]
#[allow(unused_imports)]
use crate::core::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
#[cfg(not(feature = "elgamal3"))]
#[cfg(all(feature = "offline", feature = "insecure"))]
#[allow(unused_imports)]
use crate::core::offline::decrypt_global;
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::core::transcryption::ops::{
    pseudonymize, rekey_attribute, rekey_pseudonym, transcrypt_attribute, transcrypt_pseudonym,
};

/// Pseudonymize a long encrypted pseudonym from one pseudonymization and encryption context to another.
/// Applies pseudonymization to each block independently.
pub fn pseudonymize_long(
    encrypted: &LongEncryptedPseudonym,
    pseudonymization_info: &PseudonymizationInfo,
) -> LongEncryptedPseudonym {
    let pseudonymized = encrypted
        .0
        .iter()
        .map(|block| pseudonymize(block, pseudonymization_info))
        .collect();
    LongEncryptedPseudonym(pseudonymized)
}

/// Rekey a long encrypted pseudonym from one encryption context to another.
/// Applies rekeying to each block independently.
pub fn rekey_long_pseudonym(
    encrypted: &LongEncryptedPseudonym,
    rekey_info: &PseudonymRekeyInfo,
) -> LongEncryptedPseudonym {
    let rekeyed = encrypted
        .0
        .iter()
        .map(|block| rekey_pseudonym(block, rekey_info))
        .collect();
    LongEncryptedPseudonym(rekeyed)
}

/// Rekey a long encrypted attribute from one encryption context to another.
/// Applies rekeying to each block independently.
pub fn rekey_long_attribute(
    encrypted: &LongEncryptedAttribute,
    rekey_info: &AttributeRekeyInfo,
) -> LongEncryptedAttribute {
    let rekeyed = encrypted
        .0
        .iter()
        .map(|block| rekey_attribute(block, rekey_info))
        .collect();
    LongEncryptedAttribute(rekeyed)
}

/// Transcrypt a long encrypted pseudonym from one pseudonymization and encryption context to another.
/// Applies transcryption to each block independently.
pub fn transcrypt_long_pseudonym(
    encrypted: &LongEncryptedPseudonym,
    transcryption_info: &TranscryptionInfo,
) -> LongEncryptedPseudonym {
    let transcrypted = encrypted
        .0
        .iter()
        .map(|block| transcrypt_pseudonym(block, transcryption_info))
        .collect();
    LongEncryptedPseudonym(transcrypted)
}

/// Transcrypt a long encrypted attribute from one encryption context to another.
/// Applies transcryption to each block independently.
pub fn transcrypt_long_attribute(
    encrypted: &LongEncryptedAttribute,
    transcryption_info: &TranscryptionInfo,
) -> LongEncryptedAttribute {
    let transcrypted = encrypted
        .0
        .iter()
        .map(|block| transcrypt_attribute(block, transcryption_info))
        .collect();
    LongEncryptedAttribute(transcrypted)
}
