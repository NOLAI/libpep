//! Operations for long (multi-block) data types including encryption, decryption,
//! rerandomization, rekeying, pseudonymization, and transcryption.

use super::core::{LongEncryptable, LongEncrypted, LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::arithmetic::ScalarNonZero;
use crate::high_level::core::{Encryptable, Encrypted};
#[cfg(all(feature = "global", feature = "insecure-methods"))]
#[allow(unused_imports)]
use crate::high_level::global::decrypt_global;
#[cfg(all(feature = "global", feature = "insecure-methods"))]
#[allow(unused_imports)]
use crate::high_level::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
#[cfg(not(feature = "elgamal3"))]
use crate::high_level::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey, PublicKey};
use crate::high_level::rerandomize::rerandomize_known;
use crate::high_level::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
    TranscryptionInfo,
};
use crate::high_level::transcryption::ops::{
    pseudonymize, rekey_attribute, rekey_pseudonym, transcrypt_attribute, transcrypt_pseudonym,
};
use rand_core::{CryptoRng, RngCore};

/// Rerandomize a long encrypted message, i.e. create a binary unlinkable copy of the same message.
/// Applies rerandomization to each block independently.
#[cfg(feature = "elgamal3")]
pub fn rerandomize_long<R: RngCore + CryptoRng, LE: LongEncrypted>(
    encrypted: &LE,
    rng: &mut R,
) -> LE
where
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
{
    let factors: Vec<RerandomizeFactor> = (0..encrypted.encrypted_blocks().len())
        .map(|_| RerandomizeFactor(ScalarNonZero::random(rng)))
        .collect();
    rerandomize_long_known(encrypted, &factors)
}

/// Rerandomize a long encrypted message, i.e. create a binary unlinkable copy of the same message.
/// Applies rerandomization to each block independently.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_long<R: RngCore + CryptoRng, LE: LongEncrypted, P: PublicKey>(
    encrypted: &LE,
    public_key: &P,
    rng: &mut R,
) -> LE
where
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
{
    let factors: Vec<RerandomizeFactor> = (0..encrypted.encrypted_blocks().len())
        .map(|_| RerandomizeFactor(ScalarNonZero::random(rng)))
        .collect();
    rerandomize_long_known(encrypted, public_key, &factors)
}

/// Rerandomize a long encrypted message using known rerandomization factors.
/// Applies the corresponding rerandomization factor to each block.
#[cfg(feature = "elgamal3")]
pub fn rerandomize_long_known<LE: LongEncrypted>(
    encrypted: &LE,
    factors: &[RerandomizeFactor],
) -> LE
where
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
{
    let blocks = encrypted.encrypted_blocks();
    assert_eq!(
        blocks.len(),
        factors.len(),
        "Number of blocks must match number of rerandomization factors"
    );

    let rerandomized = blocks
        .iter()
        .zip(factors.iter())
        .map(|(block, factor)| rerandomize_known(block, factor))
        .collect();
    LE::from_encrypted_blocks(rerandomized)
}

/// Rerandomize a long encrypted message using known rerandomization factors.
/// Applies the corresponding rerandomization factor to each block.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_long_known<LE: LongEncrypted, P: PublicKey>(
    encrypted: &LE,
    public_key: &P,
    factors: &[RerandomizeFactor],
) -> LE
where
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
{
    let blocks = encrypted.encrypted_blocks();
    assert_eq!(
        blocks.len(),
        factors.len(),
        "Number of blocks must match number of rerandomization factors"
    );

    let rerandomized = blocks
        .iter()
        .zip(factors.iter())
        .map(|(block, factor)| rerandomize_known(block, public_key, factor))
        .collect();
    LE::from_encrypted_blocks(rerandomized)
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(feature = "elgamal3")]
pub fn rerandomize_long_pseudonym<R: RngCore + CryptoRng>(
    encrypted: &LongEncryptedPseudonym,
    rng: &mut R,
) -> LongEncryptedPseudonym {
    rerandomize_long(encrypted, rng)
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_long_pseudonym<R: RngCore + CryptoRng>(
    encrypted: &LongEncryptedPseudonym,
    public_key: &PseudonymSessionPublicKey,
    rng: &mut R,
) -> LongEncryptedPseudonym {
    rerandomize_long(encrypted, public_key, rng)
}

/// Rerandomize a long encrypted attribute.
#[cfg(feature = "elgamal3")]
pub fn rerandomize_long_attribute<R: RngCore + CryptoRng>(
    encrypted: &LongEncryptedAttribute,
    rng: &mut R,
) -> LongEncryptedAttribute {
    rerandomize_long(encrypted, rng)
}

/// Rerandomize a long encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_long_attribute<R: RngCore + CryptoRng>(
    encrypted: &LongEncryptedAttribute,
    public_key: &AttributeSessionPublicKey,
    rng: &mut R,
) -> LongEncryptedAttribute {
    rerandomize_long(encrypted, public_key, rng)
}

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
