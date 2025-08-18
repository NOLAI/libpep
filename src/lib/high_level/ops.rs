//! High-level n-PEP operations for [encrypt]ion, [decrypt]ion and [transcrypt]ion, including batch
//! transcryption and rerandomization.

use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::internal::arithmetic::ScalarNonZero;
use crate::low_level::primitives::rsk;
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

/// Encrypt an [`Encryptable] message (a [Pseudonym] or [DataPoint]) using a [`SessionPublicKey`].
pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
    message: &E,
    public_key: &SessionPublicKey,
    rng: &mut R,
) -> E::EncryptedType {
    E::EncryptedType::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key,
        rng,
    ))
}

/// Decrypt an encrypted message using a [`SessionSecretKey`].
pub fn decrypt<E: Encrypted>(encrypted: &E, secret_key: &SessionSecretKey) -> E::UnencryptedType {
    E::UnencryptedType::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Encrypt a message using a global key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
pub fn encrypt_global<R: RngCore + CryptoRng, E: Encryptable>(
    message: &E,
    public_key: &GlobalPublicKey,
    rng: &mut R,
) -> E::EncryptedType {
    E::EncryptedType::from_value(crate::low_level::elgamal::encrypt(
        message.value(),
        public_key,
        rng,
    ))
}

/// Decrypt using a global key (notice that for most applications, this key should be discarded and thus never exist).
#[cfg(feature = "insecure-methods")]
pub fn decrypt_global<E: Encrypted>(
    encrypted: &E,
    secret_key: &GlobalSecretKey,
) -> E::UnencryptedType {
    E::UnencryptedType::from_value(crate::low_level::elgamal::decrypt(
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

/// Rekey an [`EncryptedDataPoint`] from one encryption context to another, using [`RekeyInfo`].
pub fn rekey(encrypted: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::from(crate::low_level::primitives::rekey(
        &encrypted.value,
        &rekey_info.0,
    ))
}

/// Transcrypt an encrypted message from one pseudonymization and encryption context to another,
/// using [`TranscryptionInfo`].
/// When an [`EncryptedPseudonym`] is transcrypted, the result is a pseudonymized pseudonym,
/// and when an [`EncryptedDataPoint`] is transcrypted, the result is a rekeyed data point.
pub fn transcrypt<E: Encrypted>(encrypted: &E, transcryption_info: &TranscryptionInfo) -> E {
    if E::IS_PSEUDONYM {
        E::from_value(rsk(
            encrypted.value(),
            &transcryption_info.s.0,
            &transcryption_info.k.0,
        ))
    } else {
        E::from_value(crate::low_level::primitives::rekey(
            encrypted.value(),
            &transcryption_info.k.0,
        ))
    }
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
/// Batch rekeying of a slice of [`EncryptedDataPoint`]s, using [`RekeyInfo`].
/// The order of the data points is randomly shuffled to avoid linking them.
pub fn rekey_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [EncryptedDataPoint],
    rekey_info: &RekeyInfo,
    rng: &mut R,
) -> Box<[EncryptedDataPoint]> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted.iter().map(|x| rekey(x, rekey_info)).collect()
}

/// A pair of encrypted pseudonyms and data points that relate to the same entity, used for batch transcryption.
pub type EncryptedEntityData = (Vec<EncryptedPseudonym>, Vec<EncryptedDataPoint>);

/// Batch transcryption of a slice of [`EncryptedEntityData`]s, using [`TranscryptionInfo`].
/// The order of the pairs (entities) is randomly shuffled to avoid linking them, but the internal
/// order of pseudonyms and data points for the same entity is preserved.
pub fn transcrypt_batch<R: RngCore + CryptoRng>(
    encrypted: &mut Box<[EncryptedEntityData]>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Box<[EncryptedEntityData]> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted
        .iter_mut()
        .map(|(pseudonyms, data_points)| {
            let pseudonyms = pseudonyms
                .iter()
                .map(|x| pseudonymize(x, transcryption_info))
                .collect();
            let data_points = data_points
                .iter()
                .map(|x| rekey(x, &(*transcryption_info).into()))
                .collect();
            (pseudonyms, data_points)
        })
        .collect()
}
