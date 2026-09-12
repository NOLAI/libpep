//! Polymorphic transcryption helper functions for pseudonymization, rekeying, and rerandomization.

#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::{PseudonymizationInfo, RerandomizeFactor, TranscryptionInfo};
use rand_core::{CryptoRng, Rng};

/// Polymorphic pseudonymize function for encrypted pseudonyms.
///
/// Internally uses RRSK with a freshly sampled rerandomize factor, so the
/// same pseudonym pseudonymized twice produces two unlinkable ciphertexts.
#[cfg(feature = "elgamal3")]
pub fn pseudonymize<R, E>(encrypted: &E, info: &PseudonymizationInfo, rng: &mut R) -> E
where
    E: Pseudonymizable,
    R: Rng + CryptoRng,
{
    encrypted.pseudonymize(info, rng)
}

#[cfg(not(feature = "elgamal3"))]
pub fn pseudonymize<R, E>(
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

/// Polymorphic rekey function for any encrypted type.
pub fn rekey<E>(encrypted: &E, info: &E::RekeyInfo) -> E
where
    E: Rekeyable,
{
    encrypted.rekey(info)
}

/// Polymorphic transcrypt function for any encrypted type.
///
/// Pseudonyms inside the encrypted value are rerandomized + reshuffled +
/// rekeyed with a freshly sampled `r` per pseudonym; attributes are rekeyed.
#[cfg(feature = "elgamal3")]
pub fn transcrypt<R, E>(encrypted: &E, info: &TranscryptionInfo, rng: &mut R) -> E
where
    E: Transcryptable,
    R: Rng + CryptoRng,
{
    encrypted.transcrypt(info, rng)
}

#[cfg(not(feature = "elgamal3"))]
pub fn transcrypt<R, E>(
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

/// Rerandomize an encrypted message, creating a binary unlinkable copy of the same message.
///
/// # Examples
/// ```rust,ignore
/// let rerandomized = rerandomize(&encrypted_pseudonym, &mut rng);
/// ```
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
