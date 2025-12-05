//! Transcryption, rekeying, and pseudonymization operations.
//!
//! These operations allow transforming encrypted data from one context to another.

use super::contexts::*;
use crate::base::primitives::rsk;
use crate::core::data::*;

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
    EncryptedPseudonym::from_value(crate::base::primitives::rekey(
        &encrypted.value,
        &rekey_info.0,
    ))
}

/// Rekey an [`EncryptedAttribute`] from one encryption context to another, using [`AttributeRekeyInfo`].
pub fn rekey_attribute(
    encrypted: &EncryptedAttribute,
    rekey_info: &AttributeRekeyInfo,
) -> EncryptedAttribute {
    EncryptedAttribute::from_value(crate::base::primitives::rekey(
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
        EncryptedPseudonym::from_value(crate::base::primitives::rekey(
            encrypted.value(),
            &rekey_info.scalar(),
        ))
    }
}

impl Rekeyable for EncryptedAttribute {
    type RekeyInfo = AttributeRekeyInfo;

    #[inline]
    fn rekey_impl(encrypted: &Self, rekey_info: &Self::RekeyInfo) -> Self {
        EncryptedAttribute::from_value(crate::base::primitives::rekey(
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
        EncryptedAttribute::from_value(crate::base::primitives::rekey(
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
    EncryptedAttribute::from_value(crate::base::primitives::rekey(
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::keys::{make_global_keys, make_session_keys};
    use crate::core::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};

    #[test]
    fn pseudonymize_changes_encryption_context() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let from_ctx = EncryptionContext::from("from");
        let to_ctx = EncryptionContext::from("to");
        let enc_secret = EncryptionSecret::from(b"enc".to_vec());
        let pseudo_secret = PseudonymizationSecret::from(b"pseudo".to_vec());
        let from_domain = PseudonymizationDomain::from("domain-from");
        let to_domain = PseudonymizationDomain::from("domain-to");

        let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
        let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&pseudonym, &from_session.pseudonym.public, &mut rng);

        let info = PseudonymizationInfo::new(
            &from_domain,
            &to_domain,
            &from_ctx,
            &to_ctx,
            &pseudo_secret,
            &enc_secret,
        );
        let pseudonymized = pseudonymize(&encrypted, &info);

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt_pseudonym(&pseudonymized, &to_session.pseudonym.secret)
            .expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_pseudonym(&pseudonymized, &to_session.pseudonym.secret);
        assert_ne!(pseudonym, decrypted);
    }

    #[test]
    fn rekey_pseudonym_preserves_plaintext() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let from_ctx = EncryptionContext::from("from");
        let to_ctx = EncryptionContext::from("to");
        let enc_secret = EncryptionSecret::from(b"enc".to_vec());

        let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
        let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&pseudonym, &from_session.pseudonym.public, &mut rng);

        let rekey_info = PseudonymRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
        let rekeyed = rekey_pseudonym(&encrypted, &rekey_info);

        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt_pseudonym(&rekeyed, &to_session.pseudonym.secret).expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_pseudonym(&rekeyed, &to_session.pseudonym.secret);
        assert_eq!(pseudonym, decrypted);
    }

    #[test]
    fn rekey_attribute_preserves_plaintext() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let from_ctx = EncryptionContext::from("from");
        let to_ctx = EncryptionContext::from("to");
        let enc_secret = EncryptionSecret::from(b"enc".to_vec());

        let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
        let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

        let attribute = Attribute::random(&mut rng);
        let encrypted = encrypt_attribute(&attribute, &from_session.attribute.public, &mut rng);

        let rekey_info = AttributeRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
        let rekeyed = rekey_attribute(&encrypted, &rekey_info);

        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt_attribute(&rekeyed, &to_session.attribute.secret).expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_attribute(&rekeyed, &to_session.attribute.secret);
        assert_eq!(attribute, decrypted);
    }

    #[test]
    fn transcrypt_pseudonym_applies_pseudonymization() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let from_ctx = EncryptionContext::from("from");
        let to_ctx = EncryptionContext::from("to");
        let enc_secret = EncryptionSecret::from(b"enc".to_vec());
        let pseudo_secret = PseudonymizationSecret::from(b"pseudo".to_vec());
        let from_domain = PseudonymizationDomain::from("domain-from");
        let to_domain = PseudonymizationDomain::from("domain-to");

        let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
        let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&pseudonym, &from_session.pseudonym.public, &mut rng);

        let info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            &from_ctx,
            &to_ctx,
            &pseudo_secret,
            &enc_secret,
        );
        let transcrypted = transcrypt(&encrypted, &info);

        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt_pseudonym(&transcrypted, &to_session.pseudonym.secret).expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_pseudonym(&transcrypted, &to_session.pseudonym.secret);
        assert_ne!(pseudonym, decrypted);
    }

    #[test]
    fn transcrypt_attribute_rekeys_only() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let from_ctx = EncryptionContext::from("from");
        let to_ctx = EncryptionContext::from("to");
        let enc_secret = EncryptionSecret::from(b"enc".to_vec());
        let pseudo_secret = PseudonymizationSecret::from(b"pseudo".to_vec());
        let from_domain = PseudonymizationDomain::from("domain-from");
        let to_domain = PseudonymizationDomain::from("domain-to");

        let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
        let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

        let attribute = Attribute::random(&mut rng);
        let encrypted = encrypt_attribute(&attribute, &from_session.attribute.public, &mut rng);

        let info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            &from_ctx,
            &to_ctx,
            &pseudo_secret,
            &enc_secret,
        );
        let transcrypted = transcrypt(&encrypted, &info);

        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt_attribute(&transcrypted, &to_session.attribute.secret).expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_attribute(&transcrypted, &to_session.attribute.secret);
        assert_eq!(attribute, decrypted);
    }

    #[test]
    fn polymorphic_rekey_works_for_both_types() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let from_ctx = EncryptionContext::from("from");
        let to_ctx = EncryptionContext::from("to");
        let enc_secret = EncryptionSecret::from(b"enc".to_vec());

        let from_session = make_session_keys(&global_sk, &from_ctx, &enc_secret);
        let to_session = make_session_keys(&global_sk, &to_ctx, &enc_secret);

        // Test with pseudonym
        let pseudonym = Pseudonym::random(&mut rng);
        let enc_p = encrypt_pseudonym(&pseudonym, &from_session.pseudonym.public, &mut rng);
        let rekey_p = PseudonymRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
        let rekeyed_p = rekey(&enc_p, &rekey_p);
        #[cfg(feature = "elgamal3")]
        let decrypted_p =
            decrypt_pseudonym(&rekeyed_p, &to_session.pseudonym.secret).expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted_p = decrypt_pseudonym(&rekeyed_p, &to_session.pseudonym.secret);
        assert_eq!(pseudonym, decrypted_p);

        // Test with attribute
        let attribute = Attribute::random(&mut rng);
        let enc_a = encrypt_attribute(&attribute, &from_session.attribute.public, &mut rng);
        let rekey_a = AttributeRekeyInfo::new(&from_ctx, &to_ctx, &enc_secret);
        let rekeyed_a = rekey(&enc_a, &rekey_a);
        #[cfg(feature = "elgamal3")]
        let decrypted_a =
            decrypt_attribute(&rekeyed_a, &to_session.attribute.secret).expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted_a = decrypt_attribute(&rekeyed_a, &to_session.attribute.secret);
        assert_eq!(attribute, decrypted_a);
    }
}
