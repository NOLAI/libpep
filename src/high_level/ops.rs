use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::{ScalarNonZero};
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::contexts::*;
use crate::primitives::{rekey2, rsk, rsk2};

/// Encrypt using session keys
pub fn encrypt_pseudo<R: RngCore + CryptoRng>(
    p: &Pseudonym,
    pk: &SessionPublicEncryptionKey,
    rng: &mut R,
) -> EncryptedPseudonym {
    EncryptedPseudonym {
        value: crate::elgamal::encrypt(p.value(), pk, rng),
        pc_key: p.context_key.clone(),
        ec_check: pk.clone(),
    }
}

/// Decrypt using session keys
pub fn decrypt_pseudo(p: &EncryptedPseudonym, sk: &SessionSecretEncryptionKey) -> Pseudonym {
    Pseudonym {
        value: crate::elgamal::decrypt(p.value(), &sk.0),
        context_key: p.pc_key.clone(),
    }
}



/// Decrypt using session keys
pub fn decrypt_data(p: &EncryptedPseudonym, sk: &SessionSecretEncryptionKey) -> DataPoint {
    DataPoint {
        value: crate::elgamal::decrypt(p.value(), &sk.0),
    }
}

pub fn encrypt_data<R: RngCore + CryptoRng>(
    p: &DataPoint,
    pk: &SessionPublicEncryptionKey,
    rng: &mut R,
) -> EncryptedDataPoint {
    EncryptedDataPoint {
        value: crate::elgamal::encrypt(p.value(), pk, rng),
        ec_check: pk.clone(),
    }
}


/// Encrypt for a global key
pub fn encrypt_global<R: RngCore + CryptoRng, E: Encryptable>(
    p: &E,
    pk: &GlobalPublicEncryptionKey,
    rng: &mut R,
) -> E::EncryptedTypeGlobal {
    E::EncryptedTypeGlobal::from_value(crate::elgamal::encrypt(p.value(), pk, rng))
}

/// Decrypt using a global key (notice that for most applications, this key should be discarded and thus never exist)
#[cfg(feature = "insecure-methods")]
pub fn decrypt_global<E: Encrypted>(p: &E, sk: &GlobalSecretEncryptionKey) -> E::UnencryptedType {
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
    let s = &pseudonymization_info.s.from.0.invert() * &pseudonymization_info.s.to.0;
    let k = &pseudonymization_info.k.from.0.invert() * &pseudonymization_info.k.to.0;
    EncryptedPseudonym {
        value: rsk(
            &p.value,
            &s,
            &k,
        ),
        pc_key: SessionPublicPseudonymizationKey::from(s * p.pc_key.0),
        ec_check: SessionPublicEncryptionKey::from(k * p.ec_check.0),
    }
}

/// Pseudonymize a pseudonym encrypted for a global key, from one context to another context, to be decrypted by a session key
pub fn pseudonymize_from_global(
    p: &EncryptedPseudonymGlobal,
    reshuffle_factors: Reshuffle2Factors,
    rekey_to: RekeyFactor,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from(rsk2(
        &p.value,
        &reshuffle_factors.from.0,
        &reshuffle_factors.to.0,
        &ScalarNonZero::one(),
        &rekey_to.0,
    ))
}
/// Pseudonymize a pseudonym encrypted for a session key, from one context to another context, to the global encryption context
pub fn pseudonymize_to_global(
    p: &EncryptedPseudonym,
    reshuffle_factors: Reshuffle2Factors,
    rekey_from: RekeyFactor,
) -> EncryptedPseudonymGlobal {
    EncryptedPseudonymGlobal::from_value(rsk2(
        &p.value,
        &reshuffle_factors.from.0,
        &reshuffle_factors.to.0,
        &rekey_from.0,
        &ScalarNonZero::one(),
    ))
}


/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(p: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::from(rekey2(&p.value, &rekey_info.from.0, &rekey_info.to.0))
}

/// Rekey an encrypted data point, encrypted for a global key, to be decrypted by a session key
pub fn rekey_from_global(p: &EncryptedDataPointGlobal, rekey_to: RekeyFactor) -> EncryptedDataPoint {
    EncryptedDataPoint::from(crate::primitives::rekey(&p.value, &rekey_to.0))
}
/// Rekey an encrypted data point, encrypted for a session key, to the global encryption context
pub fn rekey_to_global(p: &EncryptedDataPoint, rekey_from: RekeyFactor) -> EncryptedDataPointGlobal {
    EncryptedDataPointGlobal::from_value(crate::primitives::rekey(&p.value, &rekey_from.0.invert()))
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