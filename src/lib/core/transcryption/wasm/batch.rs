//! WASM bindings for batch transcryption operations.

use super::contexts::{WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo};
use crate::core::transcryption::batch::{
    pseudonymize_batch, rekey_batch, transcrypt_batch, EncryptedData,
};
use crate::core::transcryption::contexts::{PseudonymizationInfo, TranscryptionInfo};
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

/// A pair of encrypted pseudonyms and attributes for batch transcryption.
#[wasm_bindgen(js_name = EncryptedDataPair)]
pub struct WASMEncryptedDataPair {
    pseudonyms: Vec<WASMEncryptedPseudonym>,
    attributes: Vec<WASMEncryptedAttribute>,
}

#[wasm_bindgen(js_class = "EncryptedDataPair")]
impl WASMEncryptedDataPair {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonyms: Vec<WASMEncryptedPseudonym>,
        attributes: Vec<WASMEncryptedAttribute>,
    ) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMEncryptedPseudonym> {
        self.pseudonyms.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMEncryptedAttribute> {
        self.attributes.clone()
    }
}

/// Batch transcryption of a list of encrypted data pairs.
/// Each pair contains a list of encrypted pseudonyms and a list of encrypted attributes.
/// The order of the pairs is randomly shuffled to avoid linking them.
///
/// # Errors
///
/// Throws an error if the encrypted data do not all have the same structure.
#[wasm_bindgen(js_name = transcryptBatch)]
pub fn wasm_transcrypt_batch(
    encrypted: Vec<WASMEncryptedDataPair>,
    transcryption_info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedDataPair>, JsValue> {
    let mut rng = rand::rng();
    let enc: Vec<EncryptedData> = encrypted
        .into_iter()
        .map(|pair| {
            (
                pair.pseudonyms.into_iter().map(|p| p.0).collect(),
                pair.attributes.into_iter().map(|a| a.0).collect(),
            )
        })
        .collect();
    let info = TranscryptionInfo {
        pseudonym: transcryption_info.0.pseudonym,
        attribute: transcryption_info.0.attribute,
    };
    let result = transcrypt_batch(enc, &info, &mut rng).map_err(|e| JsValue::from_str(&e))?;
    Ok(result
        .into_iter()
        .map(|(ps, attrs)| WASMEncryptedDataPair {
            pseudonyms: ps.into_iter().map(WASMEncryptedPseudonym).collect(),
            attributes: attrs.into_iter().map(WASMEncryptedAttribute).collect(),
        })
        .collect())
}
