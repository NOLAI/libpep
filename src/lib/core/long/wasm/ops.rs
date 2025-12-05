use super::data::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
use crate::core::long::rerandomize::{rerandomize_long_attribute, rerandomize_long_pseudonym};
use crate::core::long::transcryption::{
    pseudonymize_long, rekey_long_attribute, rekey_long_pseudonym, transcrypt_long_attribute,
    transcrypt_long_pseudonym,
};
use crate::core::transcryption::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymRekeyFactor, WASMPseudonymizationInfo,
    WASMTranscryptionInfo,
};
use wasm_bindgen::prelude::*;

#[cfg(not(feature = "elgamal3"))]
use crate::core::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey};
#[cfg(not(feature = "elgamal3"))]
use crate::core::wasm::keys::{WASMAttributeSessionPublicKey, WASMPseudonymSessionPublicKey};

/// Rerandomize a long encrypted pseudonym.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeLongPseudonym)]
pub fn wasm_rerandomize_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    WASMLongEncryptedPseudonym(rerandomize_long_pseudonym(&encrypted.0, &mut rng))
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongPseudonym)]
pub fn wasm_rerandomize_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    WASMLongEncryptedPseudonym(rerandomize_long_pseudonym(&encrypted.0, &pk, &mut rng))
}

/// Rerandomize a long encrypted attribute.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeLongAttribute)]
pub fn wasm_rerandomize_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    WASMLongEncryptedAttribute(rerandomize_long_attribute(&encrypted.0, &mut rng))
}

/// Rerandomize a long encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongAttribute)]
pub fn wasm_rerandomize_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    WASMLongEncryptedAttribute(rerandomize_long_attribute(&encrypted.0, &pk, &mut rng))
}

/// Pseudonymize a long encrypted pseudonym.
#[wasm_bindgen(js_name = pseudonymizeLong)]
pub fn wasm_pseudonymize_long(
    encrypted: &WASMLongEncryptedPseudonym,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> WASMLongEncryptedPseudonym {
    WASMLongEncryptedPseudonym(pseudonymize_long(&encrypted.0, &pseudonymization_info.0))
}

/// Rekey a long encrypted pseudonym.
#[wasm_bindgen(js_name = rekeyLongPseudonym)]
pub fn wasm_rekey_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
    rekey_factor: &WASMPseudonymRekeyFactor,
) -> WASMLongEncryptedPseudonym {
    WASMLongEncryptedPseudonym(rekey_long_pseudonym(&encrypted.0, &rekey_factor.0))
}

/// Rekey a long encrypted attribute.
#[wasm_bindgen(js_name = rekeyLongAttribute)]
pub fn wasm_rekey_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
    rekey_info: &WASMAttributeRekeyInfo,
) -> WASMLongEncryptedAttribute {
    WASMLongEncryptedAttribute(rekey_long_attribute(&encrypted.0, &rekey_info.0))
}

/// Transcrypt a long encrypted pseudonym.
#[wasm_bindgen(js_name = transcryptLongPseudonym)]
pub fn wasm_transcrypt_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMLongEncryptedPseudonym {
    WASMLongEncryptedPseudonym(transcrypt_long_pseudonym(
        &encrypted.0,
        &transcryption_info.0,
    ))
}

/// Transcrypt a long encrypted attribute.
#[wasm_bindgen(js_name = transcryptLongAttribute)]
pub fn wasm_transcrypt_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMLongEncryptedAttribute {
    WASMLongEncryptedAttribute(transcrypt_long_attribute(
        &encrypted.0,
        &transcryption_info.0,
    ))
}
