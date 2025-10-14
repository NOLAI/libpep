//! High-level n-PEP operations for [encrypt]ion, [decrypt]ion and [transcrypt]ion, including batch
//! transcryption and rerandomization.
//!
//! Encryption and decryption operations use separate keys for pseudonyms and attributes.

use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::internal::arithmetic::ScalarNonZero;
use crate::low_level::primitives::rsk;
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

// Re-export traits from data_types for backwards compatibility
pub use crate::high_level::data_types::{HasGlobalKeys, HasSessionKeys};

/// Polymorphic encrypt function that works for both pseudonyms and attributes.
/// Uses the appropriate session key type based on the message type.
pub fn encrypt<M, R>(message: &M, public_key: &M::SessionPublicKey, rng: &mut R) -> M::EncryptedType
where
    M: HasSessionKeys,
    R: RngCore + CryptoRng,
{
    M::EncryptedType::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key.value(),
        rng,
    ))
}

/// Polymorphic decrypt function that works for both pseudonyms and attributes.
/// Uses the appropriate session key type based on the encrypted message type.
pub fn decrypt<E, S>(encrypted: &E, secret_key: &S) -> E::UnencryptedType
where
    E: Encrypted,
    E::UnencryptedType: HasSessionKeys<SessionSecretKey = S>,
    S: SecretKey,
{
    E::UnencryptedType::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        secret_key.value(),
    ))
}

/// Polymorphic global encrypt function that works for both pseudonyms and attributes.
/// Uses the appropriate global key type based on the message type.
pub fn encrypt_global<M, R>(
    message: &M,
    public_key: &M::GlobalPublicKey,
    rng: &mut R,
) -> M::EncryptedType
where
    M: HasGlobalKeys,
    R: RngCore + CryptoRng,
{
    M::EncryptedType::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key.value(),
        rng,
    ))
}

/// Polymorphic global decrypt function that works for both pseudonyms and attributes.
/// Uses the appropriate global key type based on the encrypted message type.
#[cfg(feature = "insecure-methods")]
pub fn decrypt_global<E, S>(encrypted: &E, secret_key: &S) -> E::UnencryptedType
where
    E: Encrypted,
    E::UnencryptedType: HasGlobalKeys<GlobalSecretKey = S>,
    S: SecretKey,
{
    E::UnencryptedType::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        secret_key.value(),
    ))
}

/// Encrypt a pseudonym using a [`PseudonymSessionPublicKey`].
pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
    message: &Pseudonym,
    public_key: &PseudonymSessionPublicKey,
    rng: &mut R,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key,
        rng,
    ))
}

/// Encrypt an attribute using a [`AttributeSessionPublicKey`].
pub fn encrypt_attribute<R: RngCore + CryptoRng>(
    message: &Attribute,
    public_key: &AttributeSessionPublicKey,
    rng: &mut R,
) -> EncryptedAttribute {
    EncryptedAttribute::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key,
        rng,
    ))
}

/// Decrypt an encrypted pseudonym using a [`PseudonymSessionSecretKey`].
pub fn decrypt_pseudonym(
    encrypted: &EncryptedPseudonym,
    secret_key: &PseudonymSessionSecretKey,
) -> Pseudonym {
    Pseudonym::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Decrypt an encrypted attribute using a [`AttributeSessionSecretKey`].
pub fn decrypt_attribute(
    encrypted: &EncryptedAttribute,
    secret_key: &AttributeSessionSecretKey,
) -> Attribute {
    Attribute::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Encrypt a pseudonym using a global key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
pub fn encrypt_pseudonym_global<R: RngCore + CryptoRng>(
    message: &Pseudonym,
    public_key: &PseudonymGlobalPublicKey,
    rng: &mut R,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key,
        rng,
    ))
}

/// Encrypt an attribute using a global key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
pub fn encrypt_attribute_global<R: RngCore + CryptoRng>(
    message: &Attribute,
    public_key: &AttributeGlobalPublicKey,
    rng: &mut R,
) -> EncryptedAttribute {
    EncryptedAttribute::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key,
        rng,
    ))
}

/// Decrypt a pseudonym using a global key (notice that for most applications, this key should be discarded and thus never exist).
#[cfg(feature = "insecure-methods")]
pub fn decrypt_pseudonym_global(
    encrypted: &EncryptedPseudonym,
    secret_key: &PseudonymGlobalSecretKey,
) -> Pseudonym {
    Pseudonym::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Decrypt an attribute using a global key (notice that for most applications, this key should be discarded and thus never exist).
#[cfg(feature = "insecure-methods")]
pub fn decrypt_attribute_global(
    encrypted: &EncryptedAttribute,
    secret_key: &AttributeGlobalSecretKey,
) -> Attribute {
    Attribute::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message.
#[cfg(feature = "elgamal3")]
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted>(encrypted: &E, rng: &mut R) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, &RerandomizeFactor(r))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    rng: &mut R,
) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, public_key, &RerandomizeFactor(r))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message,
/// using a known rerandomization factor.
#[cfg(feature = "elgamal3")]
pub fn rerandomize_known<E: Encrypted>(encrypted: &E, r: &RerandomizeFactor) -> E {
    E::from_value(crate::low_level::primitives::rerandomize(
        encrypted.value(),
        &r.0,
    ))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message,
/// using a known rerandomization factor.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_known<E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    r: &RerandomizeFactor,
) -> E {
    E::from_value(crate::low_level::primitives::rerandomize(
        encrypted.value(),
        public_key.value(),
        &r.0,
    ))
}

/// Pseudonymize an [`EncryptedPseudonym`] from one pseudonymization and encryption context to another,
/// using [`PseudonymizationInfo`].
pub fn pseudonymize(
    encrypted: &EncryptedPseudonym,
    pseudonymization_info: &PseudonymizationInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from(rsk(
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
    EncryptedPseudonym::from(crate::low_level::primitives::rekey(
        &encrypted.value,
        &rekey_info.0,
    ))
}

/// Rekey an [`EncryptedAttribute`] from one encryption context to another, using [`AttributeRekeyInfo`].
pub fn rekey_attribute(
    encrypted: &EncryptedAttribute,
    rekey_info: &AttributeRekeyInfo,
) -> EncryptedAttribute {
    EncryptedAttribute::from(crate::low_level::primitives::rekey(
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

/// Batch pseudonymization of a slice of [`EncryptedPseudonym`]s, using [`PseudonymizationInfo`].
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
pub fn pseudonymize_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [EncryptedPseudonym],
    pseudonymization_info: &PseudonymizationInfo,
    rng: &mut R,
) -> Box<[EncryptedPseudonym]> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
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
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted.iter().map(|x| rekey(x, rekey_info)).collect()
}

/// A pair of encrypted pseudonyms and attributes that relate to the same entity, used for batch transcryption.
pub type EncryptedData = (Vec<EncryptedPseudonym>, Vec<EncryptedAttribute>);

/// Batch transcryption of a slice of [`EncryptedData`]s, using [`TranscryptionInfo`].
/// The order of the pairs (entities) is randomly shuffled to avoid linking them, but the internal
/// order of pseudonyms and attributes for the same entity is preserved.
pub fn transcrypt_batch<R: RngCore + CryptoRng>(
    encrypted: &mut Box<[EncryptedData]>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Box<[EncryptedData]> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted
        .iter_mut()
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
        .collect()
}
