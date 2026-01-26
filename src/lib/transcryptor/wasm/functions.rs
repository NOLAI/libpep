//! WASM bindings for transcryption functions.

use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
#[cfg(feature = "long")]
use crate::data::wasm::long::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
use crate::factors::wasm::types::WASMPseudonymRekeyFactor;
use crate::factors::{
    AttributeRekeyInfo, PseudonymizationInfo, RerandomizeFactor, TranscryptionInfo,
};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::wasm::types::{WASMAttributeSessionPublicKey, WASMPseudonymSessionPublicKey};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey};
use crate::transcryptor::{pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt};
use wasm_bindgen::prelude::*;

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
    rekey(&encrypted.0, &rekey_info.0).into()
}

/// Rekey an encrypted attribute from one session to another.
#[wasm_bindgen(js_name = rekeyAttribute)]
pub fn wasm_rekey_attribute(
    encrypted: &WASMEncryptedAttribute,
    rekey_info: &WASMAttributeRekeyInfo,
) -> WASMEncryptedAttribute {
    rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)).into()
}

/// Transcrypt an encrypted pseudonym from one domain/session to another.
#[wasm_bindgen(js_name = transcryptPseudonym)]
pub fn wasm_transcrypt_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMEncryptedPseudonym {
    transcrypt(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}

/// Transcrypt an encrypted attribute from one session to another.
#[wasm_bindgen(js_name = transcryptAttribute)]
pub fn wasm_transcrypt_attribute(
    encrypted: &WASMEncryptedAttribute,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMEncryptedAttribute {
    transcrypt(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}

/// Rerandomize an encrypted pseudonym.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(v: &WASMEncryptedPseudonym) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize an encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(
    v: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize an encrypted attribute.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttribute)]
pub fn wasm_rerandomize_encrypted_attribute(v: &WASMEncryptedAttribute) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize an encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttribute)]
pub fn wasm_rerandomize_encrypted_attribute(
    v: &WASMEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    v: &WASMEncryptedPseudonym,
    r: &WASMScalarNonZero,
) -> WASMEncryptedPseudonym {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    v: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMEncryptedPseudonym {
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttributeKnown)]
pub fn wasm_rerandomize_encrypted_attribute_known(
    v: &WASMEncryptedAttribute,
    r: &WASMScalarNonZero,
) -> WASMEncryptedAttribute {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttributeKnown)]
pub fn wasm_rerandomize_encrypted_attribute_known(
    v: &WASMEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMEncryptedAttribute {
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

// ============================================================================
// Long Pseudonym and Attribute Functions
// ============================================================================

/// Pseudonymize a long encrypted pseudonym from one domain/session to another.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = pseudonymizeLong)]
pub fn wasm_pseudonymize_long(
    encrypted: &WASMLongEncryptedPseudonym,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> WASMLongEncryptedPseudonym {
    pseudonymize(
        &encrypted.0,
        &PseudonymizationInfo::from(pseudonymization_info),
    )
    .into()
}

/// Rekey a long encrypted pseudonym from one session to another.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = rekeyLongPseudonym)]
pub fn wasm_rekey_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
    rekey_info: &WASMPseudonymRekeyFactor,
) -> WASMLongEncryptedPseudonym {
    rekey(&encrypted.0, &rekey_info.0).into()
}

/// Rekey a long encrypted attribute from one session to another.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = rekeyLongAttribute)]
pub fn wasm_rekey_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
    rekey_info: &WASMAttributeRekeyInfo,
) -> WASMLongEncryptedAttribute {
    rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)).into()
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonym)]
pub fn wasm_rerandomize_long_encrypted_pseudonym(
    v: &WASMLongEncryptedPseudonym,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonym)]
pub fn wasm_rerandomize_long_encrypted_pseudonym(
    v: &WASMLongEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize a long encrypted attribute.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttribute)]
pub fn wasm_rerandomize_long_encrypted_attribute(
    v: &WASMLongEncryptedAttribute,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize a long encrypted attribute.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttribute)]
pub fn wasm_rerandomize_long_encrypted_attribute(
    v: &WASMLongEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize a long encrypted pseudonym using a known factor.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_long_encrypted_pseudonym_known(
    v: &WASMLongEncryptedPseudonym,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedPseudonym {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize a long encrypted pseudonym using a known factor.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_long_encrypted_pseudonym_known(
    v: &WASMLongEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedPseudonym {
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize a long encrypted attribute using a known factor.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttributeKnown)]
pub fn wasm_rerandomize_long_encrypted_attribute_known(
    v: &WASMLongEncryptedAttribute,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedAttribute {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize a long encrypted attribute using a known factor.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttributeKnown)]
pub fn wasm_rerandomize_long_encrypted_attribute_known(
    v: &WASMLongEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedAttribute {
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

// ============================================================================
// Record Functions
// ============================================================================
