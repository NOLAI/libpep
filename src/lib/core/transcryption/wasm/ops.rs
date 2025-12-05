use super::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymRekeyFactor, WASMPseudonymizationInfo,
    WASMTranscryptionInfo,
};
use crate::core::data::{
    decrypt_attribute, decrypt_pseudonym, encrypt_attribute, encrypt_pseudonym,
};
use crate::core::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::core::transcryption::ops::{
    pseudonymize, rekey_attribute, rekey_pseudonym, transcrypt_attribute, transcrypt_pseudonym,
};
use crate::core::wasm::data::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::core::wasm::keys::{
    WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey, WASMPseudonymSessionPublicKey,
    WASMPseudonymSessionSecretKey,
};
use wasm_bindgen::prelude::*;

/// Encrypt a pseudonym using a session public key.
#[wasm_bindgen(js_name = encryptPseudonym)]
pub fn wasm_encrypt_pseudonym(
    m: &WASMPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    encrypt_pseudonym(
        &m.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an encrypted pseudonym using a session secret key.
#[wasm_bindgen(js_name = decryptPseudonym)]
#[cfg(feature = "elgamal3")]
pub fn wasm_decrypt_pseudonym(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> Option<WASMPseudonym> {
    decrypt_pseudonym(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an encrypted pseudonym using a session secret key.
#[wasm_bindgen(js_name = decryptPseudonym)]
#[cfg(not(feature = "elgamal3"))]
pub fn wasm_decrypt_pseudonym(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> WASMPseudonym {
    decrypt_pseudonym(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Encrypt an attribute using a session public key.
#[wasm_bindgen(js_name = encryptAttribute)]
pub fn wasm_encrypt_attribute(
    m: &WASMAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    encrypt_attribute(
        &m.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an encrypted attribute using a session secret key.
#[wasm_bindgen(js_name = decryptAttribute)]
#[cfg(feature = "elgamal3")]
pub fn wasm_decrypt_attribute(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> Option<WASMAttribute> {
    decrypt_attribute(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an encrypted attribute using a session secret key.
#[wasm_bindgen(js_name = decryptAttribute)]
#[cfg(not(feature = "elgamal3"))]
pub fn wasm_decrypt_attribute(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> WASMAttribute {
    decrypt_attribute(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Pseudonymize an encrypted pseudonym from one domain/session to another.
#[wasm_bindgen(js_name = pseudonymize)]
pub fn wasm_pseudonymize(
    encrypted: &WASMEncryptedPseudonym,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> WASMEncryptedPseudonym {
    pseudonymize(
        &encrypted.0,
        &PseudonymizationInfo::from(pseudonymization_info),
    )
    .into()
}

/// Rekey an encrypted pseudonym from one session to another.
#[wasm_bindgen(js_name = rekeyPseudonym)]
pub fn wasm_rekey_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    rekey_info: &WASMPseudonymRekeyFactor,
) -> WASMEncryptedPseudonym {
    rekey_pseudonym(&encrypted.0, &rekey_info.0).into()
}

/// Rekey an encrypted attribute from one session to another.
#[wasm_bindgen(js_name = rekeyAttribute)]
pub fn wasm_rekey_attribute(
    encrypted: &WASMEncryptedAttribute,
    rekey_info: &WASMAttributeRekeyInfo,
) -> WASMEncryptedAttribute {
    rekey_attribute(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)).into()
}

/// Transcrypt an encrypted pseudonym from one domain/session to another.
#[wasm_bindgen(js_name = transcryptPseudonym)]
pub fn wasm_transcrypt_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMEncryptedPseudonym {
    transcrypt_pseudonym(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}

/// Transcrypt an encrypted attribute from one session to another.
#[wasm_bindgen(js_name = transcryptAttribute)]
pub fn wasm_transcrypt_attribute(
    encrypted: &WASMEncryptedAttribute,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMEncryptedAttribute {
    transcrypt_attribute(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}
