//! Polymorphic transcryption helper functions for pseudonymization, rekeying, and rerandomization.

#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::{PseudonymizationInfo, RerandomizeFactor, TranscryptionInfo};
use rand_core::{CryptoRng, RngCore};

/// Polymorphic pseudonymize function for encrypted pseudonyms.
///
/// # Examples
/// ```rust,ignore
/// let pseudonymized = pseudonymize(&encrypted_pseudonym, &pseudonymization_info);
/// ```
pub fn pseudonymize<E>(encrypted: &E, info: &PseudonymizationInfo) -> E
where
    E: Pseudonymizable,
{
    encrypted.pseudonymize(info)
}

/// Polymorphic rekey function for any encrypted type.
///
/// # Examples
/// ```rust,ignore
/// let rekeyed_pseudonym = rekey(&encrypted_pseudonym, &pseudonym_rekey_info);
/// let rekeyed_attribute = rekey(&encrypted_attribute, &attribute_rekey_info);
/// ```
pub fn rekey<E>(encrypted: &E, info: &E::RekeyInfo) -> E
where
    E: Rekeyable,
{
    encrypted.rekey(info)
}

/// Polymorphic transcrypt function for any encrypted type.
///
/// # Examples
/// ```rust,ignore
/// let transcrypted_pseudonym = transcrypt(&encrypted_pseudonym, &transcryption_info);
/// let transcrypted_attribute = transcrypt(&encrypted_attribute, &transcryption_info);
/// let transcrypted_json = transcrypt(&encrypted_json_value, &transcryption_info);
/// ```
pub fn transcrypt<E>(encrypted: &E, info: &TranscryptionInfo) -> E
where
    E: Transcryptable,
{
    encrypted.transcrypt(info)
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
    R: RngCore + CryptoRng,
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
    R: RngCore + CryptoRng,
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
