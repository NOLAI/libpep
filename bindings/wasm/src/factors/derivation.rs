//! WASM bindings for deriving factors from secrets, sessions and domains within a protocol
//! context.

use crate::factors::secrets::{WASMEncryptionSecret, WASMPseudonymizationSecret};
use crate::factors::types::{
    WASMAttributeRekeyFactor, WASMPseudonymRekeyFactor, WASMReshuffleFactor,
};
use crate::protocol::context_or_default;
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
};
use wasm_bindgen::prelude::*;

/// Derive the pseudonym rekey factor of a session from an encryption secret within the protocol
/// `context` (the default context if omitted).
#[wasm_bindgen(js_name = makePseudonymRekeyFactor)]
pub fn wasm_make_pseudonym_rekey_factor(
    secret: &WASMEncryptionSecret,
    session: &str,
    context: Option<js_sys::Object>,
) -> WASMPseudonymRekeyFactor {
    make_pseudonym_rekey_factor(
        &secret.0,
        &EncryptionContext::from(session),
        &context_or_default(context.as_ref()),
    )
    .into()
}

/// Derive the attribute rekey factor of a session from an encryption secret within the protocol
/// `context` (the default context if omitted).
#[wasm_bindgen(js_name = makeAttributeRekeyFactor)]
pub fn wasm_make_attribute_rekey_factor(
    secret: &WASMEncryptionSecret,
    session: &str,
    context: Option<js_sys::Object>,
) -> WASMAttributeRekeyFactor {
    make_attribute_rekey_factor(
        &secret.0,
        &EncryptionContext::from(session),
        &context_or_default(context.as_ref()),
    )
    .into()
}

/// Derive the reshuffle factor of a domain from a pseudonymization secret within the protocol
/// `context` (the default context if omitted).
#[wasm_bindgen(js_name = makePseudonymisationFactor)]
pub fn wasm_make_pseudonymisation_factor(
    secret: &WASMPseudonymizationSecret,
    domain: &str,
    context: Option<js_sys::Object>,
) -> WASMReshuffleFactor {
    make_pseudonymisation_factor(
        &secret.0,
        &PseudonymizationDomain::from(domain),
        &context_or_default(context.as_ref()),
    )
    .into()
}
