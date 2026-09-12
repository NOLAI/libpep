//! WASM bindings for pseudonymization domains and encryption contexts.

use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use wasm_bindgen::prelude::*;

/// The domain a pseudonym exists in (typically a user's role or usergroup).
#[derive(Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymizationDomain)]
pub struct WASMPseudonymizationDomain(pub(crate) PseudonymizationDomain);

#[wasm_bindgen(js_class = "PseudonymizationDomain")]
impl WASMPseudonymizationDomain {
    /// Create a specific pseudonymization domain from a string identifier.
    #[wasm_bindgen(constructor)]
    pub fn new(payload: &str) -> Self {
        Self(PseudonymizationDomain::from(payload))
    }

    /// Create a global pseudonymization domain.
    #[cfg(feature = "global-pseudonyms")]
    #[wasm_bindgen]
    pub fn global() -> Self {
        Self(PseudonymizationDomain::global())
    }
}

/// The context a ciphertext exists in (typically a user's session).
#[derive(Clone, Debug)]
#[wasm_bindgen(js_name = EncryptionContext)]
pub struct WASMEncryptionContext(pub(crate) EncryptionContext);

#[wasm_bindgen(js_class = "EncryptionContext")]
impl WASMEncryptionContext {
    /// Create a specific encryption context from a string identifier.
    #[wasm_bindgen(constructor)]
    pub fn new(payload: &str) -> Self {
        Self(EncryptionContext::from(payload))
    }

    /// Create a global encryption context.
    #[cfg(feature = "offline")]
    #[wasm_bindgen]
    pub fn global() -> Self {
        Self(EncryptionContext::global())
    }
}
