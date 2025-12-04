use super::data::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
#[cfg(not(feature = "elgamal3"))]
use super::keys::{WASMAttributeSessionPublicKey, WASMPseudonymSessionPublicKey};
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
#[cfg(not(feature = "elgamal3"))]
use crate::core::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey};
use crate::core::transcryption::contexts::RerandomizeFactor;
use wasm_bindgen::prelude::*;

/// Rerandomize an encrypted pseudonym.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(v: &WASMEncryptedPseudonym) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    crate::core::rerandomize::rerandomize(&v.0, &mut rng).into()
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
    crate::core::rerandomize::rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize an encrypted attribute.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttribute)]
pub fn wasm_rerandomize_encrypted_attribute(v: &WASMEncryptedAttribute) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    crate::core::rerandomize::rerandomize(&v.0, &mut rng).into()
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
    crate::core::rerandomize::rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    v: &WASMEncryptedPseudonym,
    r: &WASMScalarNonZero,
) -> WASMEncryptedPseudonym {
    crate::core::rerandomize::rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
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
    crate::core::rerandomize::rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttributeKnown)]
pub fn wasm_rerandomize_encrypted_attribute_known(
    v: &WASMEncryptedAttribute,
    r: &WASMScalarNonZero,
) -> WASMEncryptedAttribute {
    crate::core::rerandomize::rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
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
    crate::core::rerandomize::rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}
