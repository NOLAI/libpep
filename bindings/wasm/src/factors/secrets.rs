//! WASM bindings for the secrets from which factors are derived.

use derive_more::{Deref, From, Into};
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use wasm_bindgen::prelude::*;

/// Pseudonymization secret used to derive reshuffle factors from pseudonymization domains.
/// A secret is a byte array of arbitrary length.
#[derive(Clone, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymizationSecret)]
pub struct WASMPseudonymizationSecret(pub(crate) PseudonymizationSecret);

#[wasm_bindgen(js_class = "PseudonymizationSecret")]
impl WASMPseudonymizationSecret {
    /// Create a new pseudonymization secret from bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(secret: Vec<u8>) -> Self {
        Self(PseudonymizationSecret::from(secret))
    }

    /// Create a new pseudonymization secret from bytes (static method).
    #[wasm_bindgen(js_name = from)]
    pub fn wasm_from(secret: Vec<u8>) -> Self {
        Self(PseudonymizationSecret::from(secret))
    }
}

/// Encryption secret used to derive rekey factors from encryption contexts.
/// A secret is a byte array of arbitrary length.
#[derive(Clone, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = EncryptionSecret)]
pub struct WASMEncryptionSecret(pub(crate) EncryptionSecret);

#[wasm_bindgen(js_class = "EncryptionSecret")]
impl WASMEncryptionSecret {
    /// Create a new encryption secret from bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(secret: Vec<u8>) -> Self {
        Self(EncryptionSecret::from(secret))
    }

    /// Create a new encryption secret from bytes (static method).
    #[wasm_bindgen(js_name = from)]
    pub fn wasm_from(secret: Vec<u8>) -> Self {
        Self(EncryptionSecret::from(secret))
    }
}
