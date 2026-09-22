//! WASM bindings for batch transcryption operations.

use crate::data::json::WASMEncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::long::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
use crate::data::records::WASMEncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::WASMLongEncryptedRecord;
use crate::data::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::types::{
    WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
#[cfg(feature = "json")]
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::{
    WASMAttributeSessionPublicKey, WASMPseudonymSessionPublicKey, WASMSessionPublicKeys,
};
use libpep::data::records::EncryptedRecord;
#[cfg(feature = "long")]
use libpep::data::records::LongEncryptedRecord;
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey, PublicKey};
use libpep::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use wasm_bindgen::prelude::*;

#[cfg(feature = "elgamal3")]
/// Batch pseudonymize encrypted pseudonyms.
#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    pseudonymize_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "elgamal3"))]
/// Batch pseudonymize encrypted pseudonyms.
#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
    public_key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let pk = PseudonymSessionPublicKey::from_point(*public_key.0);
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    pseudonymize_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
/// Batch pseudonymize encrypted long pseudonyms.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = pseudonymizeLongBatch)]
pub fn wasm_pseudonymize_long_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
) -> Result<Vec<WASMLongEncryptedPseudonym>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    pseudonymize_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "elgamal3"))]
/// Batch pseudonymize encrypted long pseudonyms.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = pseudonymizeLongBatch)]
pub fn wasm_pseudonymize_long_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
    public_key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedPseudonym>, String> {
    let pk = PseudonymSessionPublicKey::from_point(*public_key.0);
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    pseudonymize_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
/// Batch rekey encrypted attributes.
#[wasm_bindgen(js_name = rekeyAttributeBatch)]
pub fn wasm_rekey_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    rekey_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "elgamal3"))]
/// Batch rekey encrypted attributes.
#[wasm_bindgen(js_name = rekeyAttributeBatch)]
pub fn wasm_rekey_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
    public_key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let pk = AttributeSessionPublicKey::from_point(*public_key.0);
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    rekey_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
/// Batch rekey encrypted long attributes.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = rekeyLongAttributeBatch)]
pub fn wasm_rekey_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
) -> Result<Vec<WASMLongEncryptedAttribute>, String> {
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    rekey_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "elgamal3"))]
/// Batch rekey encrypted long attributes.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = rekeyLongAttributeBatch)]
pub fn wasm_rekey_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
    public_key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedAttribute>, String> {
    let pk = AttributeSessionPublicKey::from_point(*public_key.0);
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    rekey_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
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

#[cfg(not(feature = "elgamal3"))]
/// Batch transcrypt encrypted pseudonyms.
#[wasm_bindgen(js_name = transcryptPseudonymBatch)]
pub fn wasm_transcrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMTranscryptionInfo,
    public_key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let pk = PseudonymSessionPublicKey::from_point(*public_key.0);
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
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

#[cfg(not(feature = "elgamal3"))]
/// Batch transcrypt encrypted attributes.
#[wasm_bindgen(js_name = transcryptAttributeBatch)]
pub fn wasm_transcrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMTranscryptionInfo,
    public_key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let pk = AttributeSessionPublicKey::from_point(*public_key.0);
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result| result.into_vec().into_iter().map(|e| e.into()).collect())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
/// Batch transcrypt encrypted records.
#[wasm_bindgen(js_name = transcryptRecordBatch)]
pub fn wasm_transcrypt_record_batch(
    encrypted: Vec<WASMEncryptedRecord>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedRecord>, String> {
    let mut rust_enc: Vec<_> = encrypted
        .into_iter()
        .map(|e: WASMEncryptedRecord| EncryptedRecord::from(e))
        .collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result: Box<[_]>| {
            result
                .into_vec()
                .into_iter()
                .map(WASMEncryptedRecord::from)
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "elgamal3"))]
/// Batch transcrypt encrypted records.
#[wasm_bindgen(js_name = transcryptRecordBatch)]
pub fn wasm_transcrypt_record_batch(
    encrypted: Vec<WASMEncryptedRecord>,
    info: &WASMTranscryptionInfo,
    public_key: &WASMSessionPublicKeys,
) -> Result<Vec<WASMEncryptedRecord>, String> {
    let pk = libpep::keys::SessionPublicKeys::from(public_key);
    let mut rust_enc: Vec<_> = encrypted
        .into_iter()
        .map(|e: WASMEncryptedRecord| EncryptedRecord::from(e))
        .collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result: Box<[_]>| {
            result
                .into_vec()
                .into_iter()
                .map(WASMEncryptedRecord::from)
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
/// Batch transcrypt encrypted long records.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = transcryptLongRecordBatch)]
pub fn wasm_transcrypt_long_record_batch(
    encrypted: Vec<WASMLongEncryptedRecord>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMLongEncryptedRecord>, String> {
    let mut rust_enc: Vec<_> = encrypted
        .into_iter()
        .map(|e: WASMLongEncryptedRecord| LongEncryptedRecord::from(e))
        .collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &mut rng)
        .map(|result: Box<[_]>| {
            result
                .into_vec()
                .into_iter()
                .map(WASMLongEncryptedRecord::from)
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "elgamal3"))]
/// Batch transcrypt encrypted long records.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = transcryptLongRecordBatch)]
pub fn wasm_transcrypt_long_record_batch(
    encrypted: Vec<WASMLongEncryptedRecord>,
    info: &WASMTranscryptionInfo,
    public_key: &WASMSessionPublicKeys,
) -> Result<Vec<WASMLongEncryptedRecord>, String> {
    let pk = libpep::keys::SessionPublicKeys::from(public_key);
    let mut rust_enc: Vec<_> = encrypted
        .into_iter()
        .map(|e: WASMLongEncryptedRecord| LongEncryptedRecord::from(e))
        .collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result: Box<[_]>| {
            result
                .into_vec()
                .into_iter()
                .map(WASMLongEncryptedRecord::from)
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[cfg(feature = "elgamal3")]
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

#[cfg(not(feature = "elgamal3"))]
/// Batch transcrypt encrypted JSON values.
#[cfg(feature = "json")]
#[wasm_bindgen(js_name = transcryptJSONBatch)]
pub fn wasm_transcrypt_json_batch(
    encrypted: Vec<WASMEncryptedPEPJSONValue>,
    info: &WASMTranscryptionInfo,
    public_key: &WASMSessionPublicKeys,
) -> Result<Vec<WASMEncryptedPEPJSONValue>, String> {
    let pk = libpep::keys::SessionPublicKeys::from(public_key);
    let mut rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    transcrypt_batch(&mut rust_enc, &info.0, &pk, &mut rng)
        .map(|result| {
            result
                .into_vec()
                .into_iter()
                .map(WASMEncryptedPEPJSONValue)
                .collect()
        })
        .map_err(|e| e.to_string())
}
