//! High-level n-PEP operations for encryption, decryption and transcryption, including batch
//! transcryption and rerandomization.

use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::internal::arithmetic::ScalarNonZero;
use crate::low_level::primitives::rsk;
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};

/// Encrypt using session keys
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

/// Decrypt using session keys
pub fn decrypt<E: Encrypted>(encrypted: &E, secret_key: &SessionSecretKey) -> E::UnencryptedType {
    E::UnencryptedType::from_value(crate::low_level::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Encrypt for a global key
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

/// Decrypt using a global key (notice that for most applications, this key should be discarded and thus never exist)
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

#[cfg(feature = "elgamal3")]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted>(encrypted: &E, rng: &mut R) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, &RerandomizeFactor(r))
}

#[cfg(not(feature = "elgamal3"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    rng: &mut R,
) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, public_key, &RerandomizeFactor(r))
}

#[cfg(feature = "elgamal3")]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_known<E: Encrypted>(encrypted: &E, r: &RerandomizeFactor) -> E {
    E::from_value(crate::low_level::primitives::rerandomize(
        encrypted.value(),
        &r.0,
    ))
}

#[cfg(not(feature = "elgamal3"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
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

/// Pseudonymize an encrypted pseudonym, from one context to another context
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

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(encrypted: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::from(crate::low_level::primitives::rekey(
        &encrypted.value,
        &rekey_info.0,
    ))
}

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
pub fn rekey_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [EncryptedDataPoint],
    rekey_info: &RekeyInfo,
    rng: &mut R,
) -> Box<[EncryptedDataPoint]> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted.iter().map(|x| rekey(x, rekey_info)).collect()
}

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

pub type EncryptedEntityDataPair = (Box<[EncryptedPseudonym]>, Box<[EncryptedDataPoint]>);
pub fn transcrypt_batch<R: RngCore + CryptoRng>(
    encrypted: &mut Box<[EncryptedEntityDataPair]>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Box<[EncryptedEntityDataPair]> {
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
