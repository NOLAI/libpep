use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::{ScalarNonZero};
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::contexts::*;
use crate::primitives::{rekey2, rsk2};

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
    E::from_value(crate::primitives::rerandomize(&encrypted.value(), &r))
}

#[cfg(feature = "elgamal2")]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    rng: &mut R,
) -> E {
    let r = ScalarNonZero::random(rng);
    E::from_value(crate::primitives::rerandomize(&encrypted.value(), public_key.value(), &r))
}


/// TRANSCRYPTION

/// Pseudonymize an encrypted pseudonym, from one context to another context
pub fn pseudonymize(
    p: &EncryptedPseudonym,
    pseudonymization_info: &PseudonymizationInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from(rsk2(
        &p.value,
        &pseudonymization_info.s.from.0,
        &pseudonymization_info.s.to.0,
        &pseudonymization_info.k.from.0,
        &pseudonymization_info.k.to.0,
    ))
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(p: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::from(rekey2(&p.value, &rekey_info.from.0, &rekey_info.to.0))
}

pub fn transcrypt<E: Encrypted>(encrypted: &E, transcryption_info: &TranscryptionInfo) -> E {
    if E::IS_PSEUDONYM {
        E::from_value(rsk2(
            &encrypted.value(),
            &transcryption_info.s.from.0,
            &transcryption_info.s.to.0,
            &transcryption_info.k.from.0,
            &transcryption_info.k.to.0,
        ))
    } else {
        E::from_value(rekey2(&encrypted.value(), &transcryption_info.k.from.0, &transcryption_info.k.to.0))
    }
}