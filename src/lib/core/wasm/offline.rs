use super::super::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(feature = "insecure")]
use super::super::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
#[cfg(feature = "insecure")]
use super::super::offline::{decrypt_attribute_global, decrypt_pseudonym_global};
use super::super::offline::{encrypt_attribute_global, encrypt_pseudonym_global};
use super::data::{WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym};
use super::keys::{WASMAttributeGlobalPublicKey, WASMPseudonymGlobalPublicKey};
#[cfg(feature = "insecure")]
use super::keys::{WASMAttributeGlobalSecretKey, WASMPseudonymGlobalSecretKey};
use crate::arithmetic::group_elements::GroupElement;
use wasm_bindgen::prelude::*;

/// Encrypt a pseudonym using a global public key.
#[wasm_bindgen(js_name = encryptPseudonymGlobal)]
pub fn wasm_encrypt_pseudonym_global(
    m: &WASMPseudonym,
    public_key: &WASMPseudonymGlobalPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    encrypt_pseudonym_global(
        &m.0,
        &PseudonymGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    )
    .into()
}

/// Encrypt an attribute using a global public key.
#[wasm_bindgen(js_name = encryptAttributeGlobal)]
pub fn wasm_encrypt_attribute_global(
    m: &WASMAttribute,
    public_key: &WASMAttributeGlobalPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    encrypt_attribute_global(
        &m.0,
        &AttributeGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    )
    .into()
}

/// Decrypt a pseudonym using a global secret key.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptPseudonymGlobal)]
pub fn wasm_decrypt_pseudonym_global(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymGlobalSecretKey,
) -> Option<WASMPseudonym> {
    decrypt_pseudonym_global(&v.0, &PseudonymGlobalSecretKey::from(secret_key.0 .0))
        .map(|p| p.into())
}

/// Decrypt a pseudonym using a global secret key.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptPseudonymGlobal)]
pub fn wasm_decrypt_pseudonym_global(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymGlobalSecretKey,
) -> WASMPseudonym {
    decrypt_pseudonym_global(&v.0, &PseudonymGlobalSecretKey::from(secret_key.0 .0)).into()
}

/// Decrypt an attribute using a global secret key.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptAttributeGlobal)]
pub fn wasm_decrypt_attribute_global(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeGlobalSecretKey,
) -> Option<WASMAttribute> {
    decrypt_attribute_global(&v.0, &AttributeGlobalSecretKey::from(secret_key.0 .0))
        .map(|a| a.into())
}

/// Decrypt an attribute using a global secret key.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptAttributeGlobal)]
pub fn wasm_decrypt_attribute_global(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeGlobalSecretKey,
) -> WASMAttribute {
    decrypt_attribute_global(&v.0, &AttributeGlobalSecretKey::from(secret_key.0 .0)).into()
}
