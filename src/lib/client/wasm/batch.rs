//! WASM bindings for batch client operations.

use crate::client::{decrypt_batch, encrypt_batch};
#[cfg(feature = "long")]
use crate::data::wasm::long::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};
use crate::data::wasm::simple::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::keys::wasm::types::{
    WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey, WASMPseudonymSessionPublicKey,
    WASMPseudonymSessionSecretKey,
};
use crate::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use wasm_bindgen::prelude::*;

/// Batch encrypt pseudonyms using a session public key.
#[wasm_bindgen(js_name = encryptPseudonymBatch)]
pub fn wasm_encrypt_pseudonym_batch(
    messages: Vec<WASMPseudonym>,
    key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &PseudonymSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted pseudonyms using a session secret key.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = decryptPseudonymBatch)]
pub fn wasm_decrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted pseudonyms using a session secret key.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptPseudonymBatch)]
pub fn wasm_decrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMPseudonym).collect())
        .map_err(|e| e.to_string())
}

/// Batch encrypt attributes using a session public key.
#[wasm_bindgen(js_name = encryptAttributeBatch)]
pub fn wasm_encrypt_attribute_batch(
    messages: Vec<WASMAttribute>,
    key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &AttributeSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted attributes using a session secret key.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = decryptAttributeBatch)]
pub fn wasm_decrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted attributes using a session secret key.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptAttributeBatch)]
pub fn wasm_decrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMAttribute).collect())
        .map_err(|e| e.to_string())
}

/// Batch encrypt long pseudonyms using a session public key.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = encryptLongPseudonymBatch)]
pub fn wasm_encrypt_long_pseudonym_batch(
    messages: Vec<WASMLongPseudonym>,
    key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedPseudonym>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0.clone()).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &PseudonymSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long pseudonyms using a session secret key.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptLongPseudonymBatch)]
pub fn wasm_decrypt_long_pseudonym_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMLongPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long pseudonyms using a session secret key.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptLongPseudonymBatch)]
pub fn wasm_decrypt_long_pseudonym_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMLongPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMLongPseudonym).collect())
        .map_err(|e| e.to_string())
}

/// Batch encrypt long attributes using a session public key.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = encryptLongAttributeBatch)]
pub fn wasm_encrypt_long_attribute_batch(
    messages: Vec<WASMLongAttribute>,
    key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedAttribute>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0.clone()).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &AttributeSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long attributes using a session secret key.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptLongAttributeBatch)]
pub fn wasm_decrypt_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMLongAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long attributes using a session secret key.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptLongAttributeBatch)]
pub fn wasm_decrypt_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMLongAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMLongAttribute).collect())
        .map_err(|e| e.to_string())
}
