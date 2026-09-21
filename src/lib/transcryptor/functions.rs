//! Polymorphic transcryption helper functions for pseudonymization, rekeying, and rerandomization.

#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::{PseudonymizationInfo, RerandomizeFactor, TranscryptionInfo};
use rand_core::{CryptoRng, Rng};

/// Polymorphic pseudonymize function for encrypted pseudonyms.
///
/// # Examples
/// ```rust,ignore
/// let pseudonymized = pseudonymize(&encrypted_pseudonym, &pseudonymization_info);
/// ```
/// Pseudonymize (rerandomize, reshuffle and rekey) an encrypted pseudonym.
#[cfg(feature = "elgamal3")]
pub fn pseudonymize<E, R>(encrypted: &E, info: &PseudonymizationInfo, rng: &mut R) -> E
where
    E: Pseudonymizable,
    R: Rng + CryptoRng,
{
    encrypted.pseudonymize(info, rng)
}

/// Pseudonymize (rerandomize, reshuffle and rekey) an encrypted pseudonym.
/// `public_key` is the key the ciphertext is currently encrypted under.
#[cfg(not(feature = "elgamal3"))]
pub fn pseudonymize<E, R>(
    encrypted: &E,
    info: &PseudonymizationInfo,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> E
where
    E: Pseudonymizable,
    R: Rng + CryptoRng,
{
    encrypted.pseudonymize(info, public_key, rng)
}

/// Rekey (rerandomize and rekey) an encrypted value.
#[cfg(feature = "elgamal3")]
pub fn rekey<E, R>(encrypted: &E, info: &E::RekeyInfo, rng: &mut R) -> E
where
    E: Rekeyable,
    R: Rng + CryptoRng,
{
    encrypted.rekey(info, rng)
}

/// Rekey (rerandomize and rekey) an encrypted value.
/// `public_key` is the key the ciphertext is currently encrypted under.
#[cfg(not(feature = "elgamal3"))]
pub fn rekey<E, R>(
    encrypted: &E,
    info: &E::RekeyInfo,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> E
where
    E: Rekeyable,
    R: Rng + CryptoRng,
{
    encrypted.rekey(info, public_key, rng)
}

/// Transcrypt (rerandomize, then reshuffle and/or rekey) an encrypted value.
#[cfg(feature = "elgamal3")]
pub fn transcrypt<E, R>(encrypted: &E, info: &TranscryptionInfo, rng: &mut R) -> E
where
    E: Transcryptable,
    R: Rng + CryptoRng,
{
    encrypted.transcrypt(info, rng)
}

/// Transcrypt (rerandomize, then reshuffle and/or rekey) an encrypted value.
/// `public_key` is the key the ciphertext is currently encrypted under.
#[cfg(not(feature = "elgamal3"))]
pub fn transcrypt<E, R>(
    encrypted: &E,
    info: &TranscryptionInfo,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> E
where
    E: Transcryptable,
    R: Rng + CryptoRng,
{
    encrypted.transcrypt(info, public_key, rng)
}

#[cfg(feature = "elgamal3")]
pub fn rerandomize<R, E>(encrypted: &E, rng: &mut R) -> E
where
    E: Encrypted,
    R: Rng + CryptoRng,
{
    encrypted.rerandomize(rng)
}

/// Rerandomize an encrypted message, creating a binary unlinkable copy of the same message.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize(&encrypted_pseudonym, &public_key, &mut rng);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize<R, E>(
    encrypted: &E,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> E
where
    E: Encrypted,
    R: Rng + CryptoRng,
{
    encrypted.rerandomize(public_key, rng)
}

/// Rerandomize an encrypted message using a known rerandomization factor.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize_known(&encrypted_pseudonym, &factor);
/// ```
#[cfg(feature = "elgamal3")]
pub fn rerandomize_known<E>(encrypted: &E, factor: &RerandomizeFactor) -> E
where
    E: Encrypted,
{
    encrypted.rerandomize_known(factor)
}

/// Rerandomize an encrypted message using a known rerandomization factor.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize_known(&encrypted_pseudonym, &public_key, &factor);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_known<E>(
    encrypted: &E,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    factor: &RerandomizeFactor,
) -> E
where
    E: Encrypted,
{
    encrypted.rerandomize_known(public_key, factor)
}
