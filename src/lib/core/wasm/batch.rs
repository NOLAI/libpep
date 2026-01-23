//! WASM bindings for batch transcryption operations.

use super::contexts::{WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo};
use crate::core::batch::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use crate::core::contexts::{PseudonymizationInfo, TranscryptionInfo};
use crate::core::data::records::EncryptedRecord;
use crate::core::wasm::data::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use wasm_bindgen::prelude::*;

/// Batch pseudonymization of a list of encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> Result<Vec<WASMEncryptedPseudonym>, JsValue> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = PseudonymizationInfo {
        s: pseudonymization_info.0.s,
        k: pseudonymization_info.0.k,
    };
    let result = pseudonymize_batch(&mut enc, &info, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(result
        .into_vec()
        .into_iter()
        .map(WASMEncryptedPseudonym)
        .collect())
}

/// Batch rekeying of a list of encrypted attributes.
/// The order of the attributes is randomly shuffled to avoid linking them.
#[wasm_bindgen(js_name = rekeyBatch)]
pub fn wasm_rekey_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    rekey_info: &WASMAttributeRekeyInfo,
) -> Result<Vec<WASMEncryptedAttribute>, JsValue> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let result = rekey_batch(&mut enc, &rekey_info.0, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(result
        .into_vec()
        .into_iter()
        .map(WASMEncryptedAttribute)
        .collect())
}

/// A pair of encrypted pseudonyms and attributes for batch transcryption.
/// Note: This is different from RecordEncrypted - this is specifically for batch operations.
#[wasm_bindgen(js_name = EncryptedRecord)]
pub struct WASMEncryptedRecord {
    pub(crate) pseudonyms: Vec<WASMEncryptedPseudonym>,
    pub(crate) attributes: Vec<WASMEncryptedAttribute>,
}

#[wasm_bindgen(js_class = "EncryptedRecord")]
impl WASMEncryptedRecord {
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
    encrypted: Vec<WASMEncryptedRecord>,
    transcryption_info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedRecord>, JsValue> {
    let mut rng = rand::rng();
    let mut enc: Vec<EncryptedRecord> = encrypted
        .into_iter()
        .map(|pair| {
            EncryptedRecord::new(
                pair.pseudonyms.into_iter().map(|p| p.0).collect(),
                pair.attributes.into_iter().map(|a| a.0).collect(),
            )
        })
        .collect();
    let info = TranscryptionInfo {
        pseudonym: transcryption_info.0.pseudonym,
        attribute: transcryption_info.0.attribute,
    };
    let result = transcrypt_batch(&mut enc, &info, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(result
        .into_vec()
        .into_iter()
        .map(|record| WASMEncryptedRecord {
            pseudonyms: record
                .pseudonyms
                .into_iter()
                .map(WASMEncryptedPseudonym)
                .collect(),
            attributes: record
                .attributes
                .into_iter()
                .map(WASMEncryptedAttribute)
                .collect(),
        })
        .collect())
}
