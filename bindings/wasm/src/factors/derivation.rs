//! WASM bindings for deriving factors from secrets and contexts.

use crate::factors::secrets::{WASMEncryptionSecret, WASMPseudonymizationSecret};
use crate::factors::types::{
    WASMAttributeRekeyFactor, WASMPseudonymRekeyFactor, WASMReshuffleFactor,
};
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
};
use wasm_bindgen::prelude::*;

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
