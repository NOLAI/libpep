//! WASM bindings for batch transcryption operations.

use super::contexts::{WASMAttributeRekeyInfo, WASMPseudonymizationInfo};
use crate::core::transcryption::batch::{pseudonymize_batch, rekey_batch};
use crate::core::transcryption::contexts::PseudonymizationInfo;
use crate::core::wasm::data::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use wasm_bindgen::prelude::*;

/// Batch pseudonymization of a list of encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> Vec<WASMEncryptedPseudonym> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = PseudonymizationInfo {
        s: pseudonymization_info.0.s,
        k: pseudonymization_info.0.k,
    };
    pseudonymize_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(WASMEncryptedPseudonym)
        .collect()
}

/// Batch rekeying of a list of encrypted attributes.
/// The order of the attributes is randomly shuffled to avoid linking them.
#[wasm_bindgen(js_name = rekeyBatch)]
pub fn wasm_rekey_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    rekey_info: &WASMAttributeRekeyInfo,
) -> Vec<WASMEncryptedAttribute> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    rekey_batch(&mut enc, &rekey_info.0, &mut rng)
        .into_vec()
        .into_iter()
        .map(WASMEncryptedAttribute)
        .collect()
}
