//! WASM bindings for deriving factors from secrets, sessions and domains within a protocol
//! context.

use crate::contexts::{WASMEncryptionContext, WASMPseudonymizationDomain};
use crate::factors::secrets::{WASMEncryptionSecret, WASMPseudonymizationSecret};
use crate::factors::types::{
    WASMAttributeRekeyFactor, WASMPseudonymRekeyFactor, WASMReshuffleFactor,
};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymization_factor,
};
use wasm_bindgen::prelude::*;

/// Derive the pseudonym rekey factor of a session from an encryption secret.
#[wasm_bindgen(js_name = makePseudonymRekeyFactor)]
pub fn wasm_make_pseudonym_rekey_factor(
    secret: &WASMEncryptionSecret,
    session: &WASMEncryptionContext,
) -> WASMPseudonymRekeyFactor {
    make_pseudonym_rekey_factor(&secret.0, &session.0).into()
}

/// Derive the attribute rekey factor of a session from an encryption secret.
#[wasm_bindgen(js_name = makeAttributeRekeyFactor)]
pub fn wasm_make_attribute_rekey_factor(
    secret: &WASMEncryptionSecret,
    session: &WASMEncryptionContext,
) -> WASMAttributeRekeyFactor {
    make_attribute_rekey_factor(&secret.0, &session.0).into()
}

/// Derive the reshuffle factor of a domain from a pseudonymization secret.
#[wasm_bindgen(js_name = makePseudonymizationFactor)]
pub fn wasm_make_pseudonymization_factor(
    secret: &WASMPseudonymizationSecret,
    domain: &WASMPseudonymizationDomain,
) -> WASMReshuffleFactor {
    make_pseudonymization_factor(&secret.0, &domain.0).into()
}
