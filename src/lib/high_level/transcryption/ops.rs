//! Transcryption, rekeying, and pseudonymization operations.
//!
//! These operations allow transforming encrypted data from one context to another.

use super::contexts::*;
use crate::high_level::core::*;
use crate::low_level::primitives::rsk;

/// Pseudonymize an [`EncryptedPseudonym`] from one pseudonymization and encryption context to another,
/// using [`PseudonymizationInfo`].
pub fn pseudonymize(
    encrypted: &EncryptedPseudonym,
    pseudonymization_info: &PseudonymizationInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from_value(rsk(
        &encrypted.value,
        &pseudonymization_info.s.0,
        &pseudonymization_info.k.0,
    ))
}

/// Rekey an [`EncryptedPseudonym`] from one encryption context to another, using [`PseudonymRekeyInfo`].
pub fn rekey_pseudonym(
    encrypted: &EncryptedPseudonym,
    rekey_info: &PseudonymRekeyInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from_value(crate::low_level::primitives::rekey(
        &encrypted.value,
        &rekey_info.0,
    ))
}

/// Rekey an [`EncryptedAttribute`] from one encryption context to another, using [`AttributeRekeyInfo`].
pub fn rekey_attribute(
    encrypted: &EncryptedAttribute,
    rekey_info: &AttributeRekeyInfo,
) -> EncryptedAttribute {
    EncryptedAttribute::from_value(crate::low_level::primitives::rekey(
        &encrypted.value,
        &rekey_info.0,
    ))
}

/// Trait for types that can be rekeyed.
pub trait Rekeyable: Encrypted {
    type RekeyInfo: RekeyFactor;

    /// Apply the rekey operation specific to this type.
    fn rekey_impl(encrypted: &Self, rekey_info: &Self::RekeyInfo) -> Self;
}

impl Rekeyable for EncryptedPseudonym {
    type RekeyInfo = PseudonymRekeyInfo;

    #[inline]
    fn rekey_impl(encrypted: &Self, rekey_info: &Self::RekeyInfo) -> Self {
        EncryptedPseudonym::from_value(crate::low_level::primitives::rekey(
            encrypted.value(),
            &rekey_info.scalar(),
        ))
    }
}

impl Rekeyable for EncryptedAttribute {
    type RekeyInfo = AttributeRekeyInfo;

    #[inline]
    fn rekey_impl(encrypted: &Self, rekey_info: &Self::RekeyInfo) -> Self {
        EncryptedAttribute::from_value(crate::low_level::primitives::rekey(
            encrypted.value(),
            &rekey_info.scalar(),
        ))
    }
}

/// Polymorphic rekey function that works for both pseudonyms and attributes.
/// Uses the appropriate rekey info type based on the encrypted message type.
pub fn rekey<E: Rekeyable>(encrypted: &E, rekey_info: &E::RekeyInfo) -> E {
    E::rekey_impl(encrypted, rekey_info)
}

/// Trait for types that can be transcrypted using TranscryptionInfo.
/// This trait is implemented separately for pseudonyms and attributes to provide
/// type-specific transcryption behavior without runtime dispatch.
pub trait Transcryptable: Encrypted {
    /// Apply the transcryption operation specific to this type.
    fn transcrypt_impl(encrypted: &Self, transcryption_info: &TranscryptionInfo) -> Self;
}

impl Transcryptable for EncryptedPseudonym {
    #[inline]
    fn transcrypt_impl(encrypted: &Self, transcryption_info: &TranscryptionInfo) -> Self {
        EncryptedPseudonym::from_value(rsk(
            encrypted.value(),
            &transcryption_info.pseudonym.s.0,
            &transcryption_info.pseudonym.k.0,
        ))
    }
}

impl Transcryptable for EncryptedAttribute {
    #[inline]
    fn transcrypt_impl(encrypted: &Self, transcryption_info: &TranscryptionInfo) -> Self {
        EncryptedAttribute::from_value(crate::low_level::primitives::rekey(
            encrypted.value(),
            &transcryption_info.attribute.0,
        ))
    }
}

/// Transcrypt an [`EncryptedPseudonym`] from one pseudonymization and encryption context to another,
/// using [`TranscryptionInfo`].
pub fn transcrypt_pseudonym(
    encrypted: &EncryptedPseudonym,
    transcryption_info: &TranscryptionInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from_value(rsk(
        encrypted.value(),
        &transcryption_info.pseudonym.s.0,
        &transcryption_info.pseudonym.k.0,
    ))
}

/// Transcrypt an [`EncryptedAttribute`] from one encryption context to another,
/// using [`TranscryptionInfo`].
pub fn transcrypt_attribute(
    encrypted: &EncryptedAttribute,
    transcryption_info: &TranscryptionInfo,
) -> EncryptedAttribute {
    EncryptedAttribute::from_value(crate::low_level::primitives::rekey(
        encrypted.value(),
        &transcryption_info.attribute.0,
    ))
}

/// Transcrypt an encrypted message from one pseudonymization and encryption context to another,
/// using [`TranscryptionInfo`].
///
/// When an [`EncryptedPseudonym`] is transcrypted, the result is a pseudonymized pseudonym
/// (applying both reshuffle and rekey operations).
/// When an [`EncryptedAttribute`] is transcrypted, the result is a rekeyed attribute
/// (applying only the rekey operation, as attributes cannot be reshuffled).
pub fn transcrypt<E: Transcryptable>(encrypted: &E, transcryption_info: &TranscryptionInfo) -> E {
    E::transcrypt_impl(encrypted, transcryption_info)
}
