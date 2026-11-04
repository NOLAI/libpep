//! Polymorphic transcryption helper functions for pseudonymization, rekeying, and rerandomization.

#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::types::{PseudonymizationInfo, RerandomizeFactor, TranscryptionInfo};
use crate::group::Group;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::KeyProvider;
use rand_core::{CryptoRng, Rng};

/// Pseudonymize (rerandomize, reshuffle and rekey) an encrypted pseudonym.
///
/// Reshuffling is a weak PRF: the pseudonyms must have been created from uniformly random or
/// lizard-encoded identifiers, see [`ElGamalEncryptable`](crate::data::elgamal::ElGamalEncryptable).
#[cfg(feature = "elgamal3")]
pub fn pseudonymize<G: Group, E, R>(encrypted: &E, info: &PseudonymizationInfo<G>, rng: &mut R) -> E
where
    E: Pseudonymizable<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.pseudonymize(info, rng)
}

/// Pseudonymize (rerandomize, reshuffle and rekey) an encrypted pseudonym.
///
/// Reshuffling is a weak PRF: the pseudonyms must have been created from uniformly random or
/// lizard-encoded identifiers, see [`ElGamalEncryptable`](crate::data::elgamal::ElGamalEncryptable).
/// `public_key` is the key the ciphertext is currently encrypted under.
#[cfg(not(feature = "elgamal3"))]
pub fn pseudonymize<G: Group, E, R>(
    encrypted: &E,
    info: &PseudonymizationInfo<G>,
    public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
    rng: &mut R,
) -> E
where
    E: Pseudonymizable<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.pseudonymize(info, &public_key.get_key(), rng)
}

/// Rekey (rerandomize and rekey) an encrypted value.
#[cfg(feature = "elgamal3")]
pub fn rekey<G: Group, E, R>(encrypted: &E, info: &E::RekeyInfo, rng: &mut R) -> E
where
    E: Rekeyable<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.rekey(info, rng)
}

/// Rekey (rerandomize and rekey) an encrypted value.
/// `public_key` is the key the ciphertext is currently encrypted under.
#[cfg(not(feature = "elgamal3"))]
pub fn rekey<G: Group, E, R>(
    encrypted: &E,
    info: &E::RekeyInfo,
    public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
    rng: &mut R,
) -> E
where
    E: Rekeyable<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.rekey(info, &public_key.get_key(), rng)
}

/// Transcrypt (rerandomize, then reshuffle and/or rekey) an encrypted value.
#[cfg(feature = "elgamal3")]
pub fn transcrypt<G: Group, E, R>(encrypted: &E, info: &TranscryptionInfo<G>, rng: &mut R) -> E
where
    E: Transcryptable<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.transcrypt(info, rng)
}

/// Transcrypt (rerandomize, then reshuffle and/or rekey) an encrypted value.
/// `public_key` is the key the ciphertext is currently encrypted under.
#[cfg(not(feature = "elgamal3"))]
pub fn transcrypt<G: Group, E, R>(
    encrypted: &E,
    info: &TranscryptionInfo<G>,
    public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
    rng: &mut R,
) -> E
where
    E: Transcryptable<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.transcrypt(info, &public_key.get_key(), rng)
}

#[cfg(feature = "elgamal3")]
/// Rerandomize an encrypted value with a fresh factor; with `elgamal3` the ciphertext carries its
/// public key.
///
/// # Examples
/// ```
/// # use libpep::prelude::*;
/// # let rng = &mut rand::rng();
/// # let (_global_public, global_secret) = make_global_keys(rng);
/// # let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
/// # let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
/// # let encrypted_pseudonym = encrypt(&Pseudonym::random(rng), &keys.public(), rng);
/// let rerandomized = rerandomize(&encrypted_pseudonym, rng);
/// assert_ne!(rerandomized, encrypted_pseudonym);
/// ```
pub fn rerandomize<G: Group, R, E>(encrypted: &E, rng: &mut R) -> E
where
    E: Encrypted<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.rerandomize(rng)
}

/// Rerandomize an encrypted message, creating a binary unlinkable copy of the same message.
///
/// # Examples
/// ```
/// # use libpep::prelude::*;
/// # let rng = &mut rand::rng();
/// # let (_global_public, global_secret) = make_global_keys(rng);
/// # let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
/// # let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
/// # let encrypted_pseudonym = encrypt(&Pseudonym::random(rng), &keys.public(), rng);
/// let rerandomized = rerandomize(&encrypted_pseudonym, &keys.public(), rng);
/// assert_ne!(rerandomized, encrypted_pseudonym);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize<G: Group, R, E>(
    encrypted: &E,
    public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
    rng: &mut R,
) -> E
where
    E: Encrypted<Group = G>,
    R: Rng + CryptoRng,
{
    encrypted.rerandomize(&public_key.get_key(), rng)
}

/// Rerandomize an encrypted message using a known rerandomization factor.
///
/// # Examples
/// ```
/// # use libpep::prelude::*;
/// # use libpep::group::Group;
/// # use libpep::factors::{Factor, RerandomizeFactor};
/// # let rng = &mut rand::rng();
/// # let (_global_public, global_secret) = make_global_keys(rng);
/// # let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
/// # let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
/// # let encrypted_pseudonym = encrypt(&Pseudonym::random(rng), &keys.public(), rng);
/// let factor = RerandomizeFactor::from_scalar(Ristretto255::random_scalar(rng));
/// let rerandomized = rerandomize_known(&encrypted_pseudonym, &factor);
/// assert_ne!(rerandomized, encrypted_pseudonym);
/// ```
#[cfg(feature = "elgamal3")]
pub fn rerandomize_known<G: Group, E>(encrypted: &E, factor: &RerandomizeFactor<G>) -> E
where
    E: Encrypted<Group = G>,
{
    encrypted.rerandomize_known(factor)
}

/// Rerandomize an encrypted message using a known rerandomization factor.
///
/// # Examples
/// ```
/// # use libpep::prelude::*;
/// # use libpep::group::Group;
/// # use libpep::factors::{Factor, RerandomizeFactor};
/// # let rng = &mut rand::rng();
/// # let (_global_public, global_secret) = make_global_keys(rng);
/// # let secret = RekeyingSecret::from(b"rekeying secret".to_vec());
/// # let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
/// # let encrypted_pseudonym = encrypt(&Pseudonym::random(rng), &keys.public(), rng);
/// let factor = RerandomizeFactor::from_scalar(Ristretto255::random_scalar(rng));
/// let rerandomized = rerandomize_known(&encrypted_pseudonym, &keys.public(), &factor);
/// assert_ne!(rerandomized, encrypted_pseudonym);
/// ```
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_known<G: Group, E>(
    encrypted: &E,
    public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
    factor: &RerandomizeFactor<G>,
) -> E
where
    E: Encrypted<Group = G>,
{
    encrypted.rerandomize_known(&public_key.get_key(), factor)
}
