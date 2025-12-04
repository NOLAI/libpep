//! Operations for long (multi-block) data types including encryption, decryption,
//! rerandomization, rekeying, pseudonymization, and transcryption.

use super::data::{LongEncryptable, LongEncrypted, LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::data::{Encryptable, Encrypted};
#[cfg(all(feature = "offline", feature = "insecure"))]
#[allow(unused_imports)]
use crate::core::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
#[cfg(not(feature = "elgamal3"))]
#[allow(unused_imports)]
use crate::core::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey, PublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
#[allow(unused_imports)]
use crate::core::offline::decrypt_global;
use crate::core::rerandomize::rerandomize_known;
use crate::core::transcryption::contexts::RerandomizeFactor;
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
