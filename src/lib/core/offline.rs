//! Global-key based encryption and decryption operations.
//!
//! These operations can be used when encryption happens offline and no session key is available,
//! or when using a session key may leak information.

use crate::core::data::*;
use crate::core::keys::*;
use rand_core::{CryptoRng, RngCore};

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
    M::EncryptedType::from_value(crate::base::elgamal::encrypt(
        message.value(),
        public_key.value(),
        rng,
    ))
}

/// Polymorphic global decrypt function that works for both pseudonyms and attributes.
/// Uses the appropriate global key type based on the encrypted message type.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_global<E, S>(encrypted: &E, secret_key: &S) -> Option<E::UnencryptedType>
where
    E: Encrypted,
    E::UnencryptedType: HasGlobalKeys<GlobalSecretKey = S>,
    S: SecretKey,
{
    crate::base::elgamal::decrypt(encrypted.value(), secret_key.value())
        .map(E::UnencryptedType::from_value)
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_global<E, S>(encrypted: &E, secret_key: &S) -> E::UnencryptedType
where
    E: Encrypted,
    E::UnencryptedType: HasGlobalKeys<GlobalSecretKey = S>,
    S: SecretKey,
{
    E::UnencryptedType::from_value(crate::base::elgamal::decrypt(
        encrypted.value(),
        secret_key.value(),
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
    EncryptedPseudonym::from_value(crate::base::elgamal::encrypt(
        message.value(),
        public_key.value(),
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
    EncryptedAttribute::from_value(crate::base::elgamal::encrypt(
        message.value(),
        public_key.value(),
        rng,
    ))
}

/// Decrypt a pseudonym using a global key (notice that for most applications, this key should be discarded and thus never exist).
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_pseudonym_global(
    encrypted: &EncryptedPseudonym,
    secret_key: &PseudonymGlobalSecretKey,
) -> Option<Pseudonym> {
    crate::base::elgamal::decrypt(encrypted.value(), &secret_key.0).map(Pseudonym::from_value)
}

/// Decrypt a pseudonym using a global key (notice that for most applications, this key should be discarded and thus never exist).
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_pseudonym_global(
    encrypted: &EncryptedPseudonym,
    secret_key: &PseudonymGlobalSecretKey,
) -> Pseudonym {
    Pseudonym::from_value(crate::base::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Decrypt an attribute using a global key (notice that for most applications, this key should be discarded and thus never exist).
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_attribute_global(
    encrypted: &EncryptedAttribute,
    secret_key: &AttributeGlobalSecretKey,
) -> Option<Attribute> {
    crate::base::elgamal::decrypt(encrypted.value(), &secret_key.0).map(Attribute::from_value)
}

/// Decrypt an attribute using a global key (notice that for most applications, this key should be discarded and thus never exist).
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_attribute_global(
    encrypted: &EncryptedAttribute,
    secret_key: &AttributeGlobalSecretKey,
) -> Attribute {
    Attribute::from_value(crate::base::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}
