//! WASM bindings for batch transcryption operations.

use crate::data::records::EncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::LongEncryptedRecord;
#[cfg(feature = "json")]
use crate::data::wasm::json::WASMEncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::wasm::long::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
#[cfg(feature = "long")]
use crate::data::wasm::records::WASMLongRecordEncrypted;
use crate::data::wasm::records::WASMRecordEncrypted;
use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
use crate::factors::{AttributeRekeyInfo, PseudonymizationInfo};
use crate::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use wasm_bindgen::prelude::*;

/// Batch pseudonymize encrypted pseudonyms.
#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    pseudonymize_batch(&mut rust_enc, &PseudonymizationInfo::from(info.0), &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch pseudonymize encrypted long pseudonyms.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = pseudonymizeLongBatch)]
pub fn wasm_pseudonymize_long_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
) -> Result<Vec<WASMLongEncryptedPseudonym>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    pseudonymize_batch(&mut rust_enc, &PseudonymizationInfo::from(info.0), &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch rekey encrypted attributes.
#[wasm_bindgen(js_name = rekeyAttributeBatch)]
pub fn wasm_rekey_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    rekey_batch(&mut rust_enc, &AttributeRekeyInfo::from(info.0), &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch rekey encrypted long attributes.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = rekeyLongAttributeBatch)]
pub fn wasm_rekey_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
) -> Result<Vec<WASMLongEncryptedAttribute>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    rekey_batch(&mut rust_enc, &AttributeRekeyInfo::from(info.0), &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch transcrypt encrypted pseudonyms.
#[wasm_bindgen(js_name = transcryptPseudonymBatch)]
pub fn wasm_transcrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch transcrypt encrypted attributes.
#[wasm_bindgen(js_name = transcryptAttributeBatch)]
pub fn wasm_transcrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch transcrypt encrypted records.
#[wasm_bindgen(js_name = transcryptRecordBatch)]
pub fn wasm_transcrypt_record_batch(
    encrypted: Vec<WASMRecordEncrypted>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMRecordEncrypted>, String> {
    let mut rust_enc: Vec<_> = encrypted
        .into_iter()
        .map(|e: WASMRecordEncrypted| EncryptedRecord::from(e))
        .collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result: Box<[_]>| {
            result
                .into_vec()
                .into_iter()
                .map(WASMRecordEncrypted::from)
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// Batch transcrypt encrypted long records.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = transcryptLongRecordBatch)]
pub fn wasm_transcrypt_long_record_batch(
    encrypted: Vec<WASMLongRecordEncrypted>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMLongRecordEncrypted>, String> {
    let mut rust_enc: Vec<_> = encrypted
        .into_iter()
        .map(|e: WASMLongRecordEncrypted| LongEncryptedRecord::from(e))
        .collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result: Box<[_]>| {
            result
                .into_vec()
                .into_iter()
                .map(WASMLongRecordEncrypted::from)
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// Batch transcrypt encrypted JSON values.
#[cfg(feature = "json")]
#[wasm_bindgen(js_name = transcryptJSONBatch)]
pub fn wasm_transcrypt_json_batch(
    encrypted: Vec<WASMEncryptedPEPJSONValue>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedPEPJSONValue>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result| {
            result
                .into_vec()
                .into_iter()
                .map(WASMEncryptedPEPJSONValue)
                .collect()
        })
        .map_err(|e| e.to_string())
}
