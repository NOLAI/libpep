use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::{ScalarNonZero};
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::contexts::*;
use crate::primitives::{rsk};

/// Encrypt using session keys
pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
    p: &E,
    pk: &SessionPublicKey,
    rng: &mut R,
) -> E::EncryptedType {
    E::EncryptedType::from_value(crate::elgamal::encrypt(p.value(), pk, rng))
}

/// Decrypt using session keys
pub fn decrypt<E: Encrypted>(p: &E, sk: &SessionSecretKey) -> E::UnencryptedType {
    E::UnencryptedType::from_value(crate::elgamal::decrypt(p.value(), &sk.0))
}

/// Encrypt for a global key
pub fn encrypt_global<R: RngCore + CryptoRng, E: Encryptable>(
    p: &E,
    pk: &GlobalPublicKey,
    rng: &mut R,
) -> E::EncryptedType {
    E::EncryptedType::from_value(crate::elgamal::encrypt(p.value(), pk, rng))
}

/// Decrypt using a global key (notice that for most applications, this key should be discarded and thus never exist)
#[cfg(feature = "insecure-methods")]
pub fn decrypt_global<E: Encrypted>(p: &E, sk: &GlobalSecretKey) -> E::UnencryptedType {
    E::UnencryptedType::from_value(crate::elgamal::decrypt(p.value(), &sk.0))
}

#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted>(
    encrypted: &E,
    rng: &mut R,
) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, &RerandomizeFactor(r))
}

#[cfg(feature = "elgamal2")]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    rng: &mut R,
) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, public_key, &RerandomizeFactor(r))
}


#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_known<E: Encrypted>(
    encrypted: &E,
    r: &RerandomizeFactor,
) -> E {
    E::from_value(crate::primitives::rerandomize(&encrypted.value(), r))
}

#[cfg(feature = "elgamal2")]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_known<E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    r: &RerandomizeFactor,
) -> E {
    E::from_value(crate::primitives::rerandomize(&encrypted.value(), public_key.value(), &r.0))
}

/// TRANSCRYPTION

/// Pseudonymize an encrypted pseudonym, from one context to another context
pub fn pseudonymize(
    p: &EncryptedPseudonym,
    pseudonymization_info: &PseudonymizationInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from(rsk(
        &p.value,
        &pseudonymization_info.s.0,
        &pseudonymization_info.k.0,
    ))
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(p: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::from(crate::primitives::rekey(&p.value, &rekey_info.0))
}

pub fn pseudonymize_batch<R: RngCore + CryptoRng>(
    encrypted: &mut [EncryptedPseudonym],
    pseudonymization_info: &PseudonymizationInfo,
    rng: &mut R,
) -> Box<[EncryptedPseudonym]> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted.iter()
        .map(|x| pseudonymize(x, pseudonymization_info))
        .collect()
}
pub fn rekey_batch<R: RngCore + CryptoRng>(encrypted: &mut [EncryptedDataPoint], rekey_info: &RekeyInfo, rng: &mut R) -> Box<[EncryptedDataPoint]> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted.iter()
        .map(|x| rekey(x, rekey_info))
        .collect()
}

pub fn transcrypt<E: Encrypted>(encrypted: &E, transcryption_info: &TranscryptionInfo) -> E {
    if E::IS_PSEUDONYM {
        E::from_value(rsk(
            &encrypted.value(),
            &transcryption_info.s.0,
            &transcryption_info.k.0,
        ))
    } else {
        E::from_value(crate::primitives::rekey(&encrypted.value(), &transcryption_info.k.0))
    }
}

pub fn transcrypt_batch<R: RngCore + CryptoRng>(
    encrypted: &mut Vec<(Vec<EncryptedPseudonym>, Vec<EncryptedDataPoint>)>,
    transcryption_info: &TranscryptionInfo,
    rng: &mut R,
) -> Vec<(Vec<EncryptedPseudonym>, Vec<EncryptedDataPoint>)> {
    encrypted.shuffle(rng); // Shuffle the order to avoid linking
    encrypted.iter_mut()
        .map(|(pseudonyms, data_points)| {
            let pseudonyms = pseudonyms.iter().map(|x| pseudonymize(x, &transcryption_info)).collect();
            let data_points = data_points.iter().map(|x| rekey(x, &(*transcryption_info).into())).collect();
            (pseudonyms, data_points)
        }).collect()
}
