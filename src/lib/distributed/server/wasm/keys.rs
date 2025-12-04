use super::super::keys::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_shares,
};
use super::setup::WASMBlindingFactor;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::core::transcryption::contexts::{AttributeRekeyFactor, PseudonymRekeyFactor};
use crate::distributed::client::wasm::keys::{
    WASMAttributeSessionKeyShare, WASMPseudonymSessionKeyShare, WASMSessionKeyShares,
};
use wasm_bindgen::prelude::*;

/// Creates a pseudonym session key share.
#[wasm_bindgen(js_name = makePseudonymSessionKeyShare)]
pub fn wasm_make_pseudonym_session_key_share(
    rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMPseudonymSessionKeyShare {
    WASMPseudonymSessionKeyShare(make_pseudonym_session_key_share(
        &PseudonymRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Creates an attribute session key share.
#[wasm_bindgen(js_name = makeAttributeSessionKeyShare)]
pub fn wasm_make_attribute_session_key_share(
    rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMAttributeSessionKeyShare {
    WASMAttributeSessionKeyShare(make_attribute_session_key_share(
        &AttributeRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Creates session key shares.
#[wasm_bindgen(js_name = makeSessionKeyShares)]
pub fn wasm_make_session_key_shares(
    pseudonym_rekey_factor: &WASMScalarNonZero,
    attribute_rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMSessionKeyShares {
    WASMSessionKeyShares(make_session_key_shares(
        &PseudonymRekeyFactor::from(pseudonym_rekey_factor.0),
        &AttributeRekeyFactor::from(attribute_rekey_factor.0),
        &blinding_factor.0,
    ))
}
