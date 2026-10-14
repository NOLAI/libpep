//! WASM bindings for pseudonymization domains and encryption contexts.

use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::derivation::MAX_INPUT_LENGTH;
use wasm_bindgen::prelude::*;

/// The factor derivation needs the identifier shorter than 2^16 bytes.
fn checked(payload: &str) -> Result<&str, JsError> {
    if payload.len() >= MAX_INPUT_LENGTH {
        return Err(JsError::new(&format!(
            "must be shorter than {MAX_INPUT_LENGTH} bytes"
        )));
    }
    Ok(payload)
}

/// The domain a pseudonym exists in (typically a user's role or usergroup).
#[derive(Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymizationDomain)]
pub struct WASMPseudonymizationDomain(pub(crate) PseudonymizationDomain);

#[wasm_bindgen(js_class = "PseudonymizationDomain")]
impl WASMPseudonymizationDomain {
    /// Create a specific pseudonymization domain from a string identifier.
    #[wasm_bindgen(constructor)]
    pub fn new(payload: &str) -> Result<WASMPseudonymizationDomain, JsError> {
        Ok(Self(PseudonymizationDomain::from(checked(payload)?)))
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
    pub fn new(payload: &str) -> Result<WASMEncryptionContext, JsError> {
        Ok(Self(EncryptionContext::from(checked(payload)?)))
    }

    /// Create a global encryption context.
    #[cfg(feature = "offline")]
    #[wasm_bindgen]
    pub fn global() -> Self {
        Self(EncryptionContext::global())
    }
}
