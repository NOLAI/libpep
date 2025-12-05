//! WASM bindings for batch operations on long (multi-block) data types.

use super::data::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
use crate::core::long::batch::{
    pseudonymize_long_batch, rekey_long_attribute_batch, rekey_long_pseudonym_batch,
    transcrypt_long_batch, LongEncryptedData,
};
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::core::transcryption::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymRekeyFactor, WASMPseudonymizationInfo,
    WASMTranscryptionInfo,
};
use wasm_bindgen::prelude::*;

/// Batch pseudonymization of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[wasm_bindgen(js_name = pseudonymizeLongBatch)]
pub fn wasm_pseudonymize_long_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> Vec<WASMLongEncryptedPseudonym> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = PseudonymizationInfo {
        s: pseudonymization_info.0.s,
        k: pseudonymization_info.0.k,
    };
    pseudonymize_long_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(WASMLongEncryptedPseudonym)
        .collect()
}

/// Batch rekeying of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[wasm_bindgen(js_name = rekeyLongPseudonymBatch)]
pub fn wasm_rekey_long_pseudonym_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    rekey_info: &WASMPseudonymRekeyFactor,
) -> Vec<WASMLongEncryptedPseudonym> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    rekey_long_pseudonym_batch(&mut enc, &rekey_info.0, &mut rng)
        .into_vec()
        .into_iter()
        .map(WASMLongEncryptedPseudonym)
        .collect()
}

/// Batch rekeying of long encrypted attributes.
/// The order of the attributes is randomly shuffled to avoid linking them.
#[wasm_bindgen(js_name = rekeyLongAttributeBatch)]
pub fn wasm_rekey_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    rekey_info: &WASMAttributeRekeyInfo,
) -> Vec<WASMLongEncryptedAttribute> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = AttributeRekeyInfo::from(rekey_info.0);
    rekey_long_attribute_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(WASMLongEncryptedAttribute)
        .collect()
}

/// A pair of long encrypted pseudonyms and attributes for batch transcryption.
#[wasm_bindgen(js_name = LongEncryptedDataPair)]
pub struct WASMLongEncryptedDataPair {
    pseudonyms: Vec<WASMLongEncryptedPseudonym>,
    attributes: Vec<WASMLongEncryptedAttribute>,
}

#[wasm_bindgen(js_class = "LongEncryptedDataPair")]
impl WASMLongEncryptedDataPair {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonyms: Vec<WASMLongEncryptedPseudonym>,
        attributes: Vec<WASMLongEncryptedAttribute>,
    ) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMLongEncryptedPseudonym> {
        self.pseudonyms.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMLongEncryptedAttribute> {
        self.attributes.clone()
    }
}

/// Batch transcryption of long encrypted data.
/// Each item contains a list of long encrypted pseudonyms and a list of long encrypted attributes.
/// The order of the items is randomly shuffled to avoid linking them.
///
/// # Errors
///
/// Throws an error if the encrypted data do not all have the same structure.
#[wasm_bindgen(js_name = transcryptLongBatch)]
pub fn wasm_transcrypt_long_batch(
    encrypted: Vec<WASMLongEncryptedDataPair>,
    transcryption_info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMLongEncryptedDataPair>, JsValue> {
    let mut rng = rand::rng();
    let enc: Vec<LongEncryptedData> = encrypted
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
    let result = transcrypt_long_batch(enc, &info, &mut rng).map_err(|e| JsValue::from_str(&e))?;
    Ok(result
        .into_iter()
        .map(|(ps, attrs)| WASMLongEncryptedDataPair {
            pseudonyms: ps.into_iter().map(WASMLongEncryptedPseudonym).collect(),
            attributes: attrs.into_iter().map(WASMLongEncryptedAttribute).collect(),
        })
        .collect())
}
