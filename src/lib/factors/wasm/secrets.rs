//! WASM bindings for secret types and factor derivation functions.

use crate::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::factors::wasm::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::factors::*;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

use crate::factors::wasm::types::{
    WASMAttributeRekeyFactor, WASMPseudonymRekeyFactor, WASMReshuffleFactor,
};

/// Pseudonymization secret used to derive a [`ReshuffleFactor`] from a [`PseudonymizationDomain`].
///
/// [`ReshuffleFactor`]: crate::factors::ReshuffleFactor
/// [`PseudonymizationDomain`]: crate::factors::contexts::PseudonymizationDomain
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

/// Encryption secret used to derive rekey factors from an [`EncryptionContext`].
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

/// Derive a pseudonym rekey factor from a secret and a context.
#[wasm_bindgen(js_name = makePseudonymRekeyFactor)]
pub fn wasm_make_pseudonym_rekey_factor(
    secret: &WASMEncryptionSecret,
    context: &str,
) -> WASMPseudonymRekeyFactor {
    make_pseudonym_rekey_factor(&secret.0, &EncryptionContext::from(context)).into()
}

/// Derive an attribute rekey factor from a secret and a context.
#[wasm_bindgen(js_name = makeAttributeRekeyFactor)]
pub fn wasm_make_attribute_rekey_factor(
    secret: &WASMEncryptionSecret,
    context: &str,
) -> WASMAttributeRekeyFactor {
    make_attribute_rekey_factor(&secret.0, &EncryptionContext::from(context)).into()
}

/// Derive a pseudonymisation factor from a secret and a domain.
#[wasm_bindgen(js_name = makePseudonymisationFactor)]
pub fn wasm_make_pseudonymisation_factor(
    secret: &WASMPseudonymizationSecret,
    domain: &str,
) -> WASMReshuffleFactor {
    make_pseudonymisation_factor(&secret.0, &PseudonymizationDomain::from(domain)).into()
}
