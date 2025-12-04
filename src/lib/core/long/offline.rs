use crate::core::data::HasGlobalKeys;
#[cfg(feature = "insecure")]
use crate::core::data::{Encryptable, Encrypted};
use crate::core::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(feature = "insecure")]
use crate::core::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
#[cfg(feature = "insecure")]
use crate::core::long::data::LongEncrypted;
use crate::core::long::data::{
    LongAttribute, LongEncryptable, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
#[cfg(feature = "insecure")]
use crate::core::offline::decrypt_global;
use crate::core::offline::encrypt_global;
use rand_core::{CryptoRng, RngCore};

/// Polymorphic global encrypt function for long (multi-block) data types.
/// Uses `ops::encrypt_global` for each individual block.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
pub fn encrypt_long_global<L, R>(
    message: &L,
    public_key: &<L::Block as HasGlobalKeys>::GlobalPublicKey,
    rng: &mut R,
) -> L::EncryptedType
where
    L: LongEncryptable,
    L::Block: HasGlobalKeys,
    R: RngCore + CryptoRng,
{
    let encrypted = message
        .blocks()
        .iter()
        .map(|block| encrypt_global(block, public_key, rng))
        .collect();
    L::from_encrypted_blocks(encrypted)
}

/// Polymorphic global decrypt function for long (multi-block) encrypted data types.
/// Uses `ops::decrypt_global` for each individual block.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_long_global<LE>(
    encrypted: &LE,
    secret_key: &<<LE::UnencryptedType as LongEncryptable>::Block as HasGlobalKeys>::GlobalSecretKey,
) -> Option<LE::UnencryptedType>
where
    LE: LongEncrypted,
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
    <LE::UnencryptedType as LongEncryptable>::Block: HasGlobalKeys,
{
    let decrypted: Option<Vec<_>> = encrypted
        .encrypted_blocks()
        .iter()
        .map(|block| decrypt_global(block, secret_key))
        .collect();
    decrypted.map(LE::from_decrypted_blocks)
}

/// Uses `ops::decrypt_global` for each individual block.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_long_global<LE>(
    encrypted: &LE,
    secret_key: &<<LE::UnencryptedType as LongEncryptable>::Block as HasGlobalKeys>::GlobalSecretKey,
) -> LE::UnencryptedType
where
    LE: LongEncrypted,
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
    <LE::UnencryptedType as LongEncryptable>::Block: HasGlobalKeys,
{
    let decrypted = encrypted
        .encrypted_blocks()
        .iter()
        .map(|block| decrypt_global(block, secret_key))
        .collect();
    LE::from_decrypted_blocks(decrypted)
}

/// Encrypt a long pseudonym using a global key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
pub fn encrypt_long_pseudonym_global<R: RngCore + CryptoRng>(
    message: &LongPseudonym,
    public_key: &PseudonymGlobalPublicKey,
    rng: &mut R,
) -> LongEncryptedPseudonym {
    encrypt_long_global(message, public_key, rng)
}

/// Decrypt a long encrypted pseudonym using a global key.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_long_pseudonym_global(
    encrypted: &LongEncryptedPseudonym,
    secret_key: &PseudonymGlobalSecretKey,
) -> Option<LongPseudonym> {
    decrypt_long_global(encrypted, secret_key)
}

/// Decrypt a long encrypted pseudonym using a global key.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_long_pseudonym_global(
    encrypted: &LongEncryptedPseudonym,
    secret_key: &PseudonymGlobalSecretKey,
) -> LongPseudonym {
    decrypt_long_global(encrypted, secret_key)
}

/// Encrypt a long attribute using a global key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
pub fn encrypt_long_attribute_global<R: RngCore + CryptoRng>(
    message: &LongAttribute,
    public_key: &AttributeGlobalPublicKey,
    rng: &mut R,
) -> LongEncryptedAttribute {
    encrypt_long_global(message, public_key, rng)
}

/// Decrypt a long encrypted attribute using a global key.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_long_attribute_global(
    encrypted: &LongEncryptedAttribute,
    secret_key: &AttributeGlobalSecretKey,
) -> Option<LongAttribute> {
    decrypt_long_global(encrypted, secret_key)
}

/// Decrypt a long encrypted attribute using a global key.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_long_attribute_global(
    encrypted: &LongEncryptedAttribute,
    secret_key: &AttributeGlobalSecretKey,
) -> LongAttribute {
    decrypt_long_global(encrypted, secret_key)
}
