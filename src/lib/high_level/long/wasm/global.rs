use super::core::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};
use crate::arithmetic::GroupElement;
use crate::high_level::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
use crate::high_level::long::global::{
    encrypt_long_attribute_global, encrypt_long_pseudonym_global,
};
use crate::high_level::wasm::keys::{WASMAttributeGlobalPublicKey, WASMPseudonymGlobalPublicKey};
use wasm_bindgen::prelude::*;

#[cfg(feature = "insecure-methods")]
use crate::high_level::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
#[cfg(feature = "insecure-methods")]
use crate::high_level::long::global::{
    decrypt_long_attribute_global, decrypt_long_pseudonym_global,
};
#[cfg(feature = "insecure-methods")]
use crate::high_level::wasm::keys::{WASMAttributeGlobalSecretKey, WASMPseudonymGlobalSecretKey};

/// Encrypt a long pseudonym using a global key.
#[wasm_bindgen(js_name = encryptLongPseudonymGlobal)]
pub fn wasm_encrypt_long_pseudonym_global(
    message: &WASMLongPseudonym,
    public_key: &WASMPseudonymGlobalPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    WASMLongEncryptedPseudonym(encrypt_long_pseudonym_global(
        &message.0,
        &PseudonymGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Decrypt a long encrypted pseudonym using a global key.
#[cfg(feature = "insecure-methods")]
#[wasm_bindgen(js_name = decryptLongPseudonymGlobal)]
pub fn wasm_decrypt_long_pseudonym_global(
    encrypted: &WASMLongEncryptedPseudonym,
    secret_key: &WASMPseudonymGlobalSecretKey,
) -> WASMLongPseudonym {
    WASMLongPseudonym(decrypt_long_pseudonym_global(
        &encrypted.0,
        &PseudonymGlobalSecretKey::from(secret_key.0 .0),
    ))
}

/// Encrypt a long attribute using a global key.
#[wasm_bindgen(js_name = encryptLongAttributeGlobal)]
pub fn wasm_encrypt_long_attribute_global(
    message: &WASMLongAttribute,
    public_key: &WASMAttributeGlobalPublicKey,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    WASMLongEncryptedAttribute(encrypt_long_attribute_global(
        &message.0,
        &AttributeGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Decrypt a long encrypted attribute using a global key.
#[cfg(feature = "insecure-methods")]
#[wasm_bindgen(js_name = decryptLongAttributeGlobal)]
pub fn wasm_decrypt_long_attribute_global(
    encrypted: &WASMLongEncryptedAttribute,
    secret_key: &WASMAttributeGlobalSecretKey,
) -> WASMLongAttribute {
    WASMLongAttribute(decrypt_long_attribute_global(
        &encrypted.0,
        &AttributeGlobalSecretKey::from(secret_key.0 .0),
    ))
}
