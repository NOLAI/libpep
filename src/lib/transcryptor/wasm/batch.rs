//! WASM bindings for batch transcryption operations.
//!
//! Wrap [`EncryptedBatch`](crate::data::batch::EncryptedBatch) so JS callers
//! continue to receive plain `Vec<...>` while benefiting from the new
//! struct's lockstep public-key updates internally.

use crate::data::batch::EncryptedBatch;
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
#[cfg(not(feature = "elgamal3"))]
use crate::keys::wasm::types::{
    WASMAttributeSessionPublicKey, WASMPseudonymSessionPublicKey, WASMSessionKeys,
};
use wasm_bindgen::prelude::*;

/// Batch pseudonymize encrypted pseudonyms.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
    public_key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
    let mut batch = EncryptedBatch::new(items, pk).map_err(|e| e.to_string())?;
    batch
        .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

/// Batch pseudonymize encrypted long pseudonyms.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = pseudonymizeLongBatch)]
pub fn wasm_pseudonymize_long_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
) -> Result<Vec<WASMLongEncryptedPseudonym>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = pseudonymizeLongBatch)]
pub fn wasm_pseudonymize_long_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    info: &WASMPseudonymizationInfo,
    public_key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedPseudonym>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
    let mut batch = EncryptedBatch::new(items, pk).map_err(|e| e.to_string())?;
    batch
        .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

/// Batch rekey encrypted attributes.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rekeyAttributeBatch)]
pub fn wasm_rekey_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rekeyAttributeBatch)]
pub fn wasm_rekey_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
    public_key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let pk = crate::keys::AttributeSessionPublicKey::from(public_key.0 .0);
    let mut batch = EncryptedBatch::new(items, pk).map_err(|e| e.to_string())?;
    batch
        .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

/// Batch rekey encrypted long attributes.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rekeyLongAttributeBatch)]
pub fn wasm_rekey_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
) -> Result<Vec<WASMLongEncryptedAttribute>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rekeyLongAttributeBatch)]
pub fn wasm_rekey_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    info: &WASMAttributeRekeyInfo,
    public_key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedAttribute>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    let pk = crate::keys::AttributeSessionPublicKey::from(public_key.0 .0);
    let mut batch = EncryptedBatch::new(items, pk).map_err(|e| e.to_string())?;
    batch
        .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

/// Batch transcrypt encrypted pseudonyms.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = transcryptPseudonymBatch)]
pub fn wasm_transcrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = transcryptPseudonymBatch)]
pub fn wasm_transcrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    info: &WASMTranscryptionInfo,
    public_key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
    let mut batch = EncryptedBatch::new(items, pk).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

/// Batch transcrypt encrypted attributes.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = transcryptAttributeBatch)]
pub fn wasm_transcrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = transcryptAttributeBatch)]
pub fn wasm_transcrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    info: &WASMTranscryptionInfo,
    public_key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    let mut rng = rand::rng();
    let pk = crate::keys::AttributeSessionPublicKey::from(public_key.0 .0);
    let mut batch = EncryptedBatch::new(items, pk).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch.into_items().into_iter().map(|e| e.into()).collect())
}

/// Batch transcrypt encrypted records.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = transcryptRecordBatch)]
pub fn wasm_transcrypt_record_batch(
    encrypted: Vec<WASMRecordEncrypted>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMRecordEncrypted>, String> {
    let items: Vec<EncryptedRecord> = encrypted.into_iter().map(EncryptedRecord::from).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch
        .into_items()
        .into_iter()
        .map(WASMRecordEncrypted::from)
        .collect())
}

#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = transcryptRecordBatch)]
pub fn wasm_transcrypt_record_batch(
    encrypted: Vec<WASMRecordEncrypted>,
    info: &WASMTranscryptionInfo,
    session_keys: &WASMSessionKeys,
) -> Result<Vec<WASMRecordEncrypted>, String> {
    let items: Vec<EncryptedRecord> = encrypted.into_iter().map(EncryptedRecord::from).collect();
    let mut rng = rand::rng();
    let keys: crate::keys::SessionKeys = (*session_keys).into();
    let mut batch = EncryptedBatch::new(items, keys).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch
        .into_items()
        .into_iter()
        .map(WASMRecordEncrypted::from)
        .collect())
}

/// Batch transcrypt encrypted long records.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = transcryptLongRecordBatch)]
pub fn wasm_transcrypt_long_record_batch(
    encrypted: Vec<WASMLongRecordEncrypted>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMLongRecordEncrypted>, String> {
    let items: Vec<LongEncryptedRecord> = encrypted
        .into_iter()
        .map(LongEncryptedRecord::from)
        .collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch
        .into_items()
        .into_iter()
        .map(WASMLongRecordEncrypted::from)
        .collect())
}

#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = transcryptLongRecordBatch)]
pub fn wasm_transcrypt_long_record_batch(
    encrypted: Vec<WASMLongRecordEncrypted>,
    info: &WASMTranscryptionInfo,
    session_keys: &WASMSessionKeys,
) -> Result<Vec<WASMLongRecordEncrypted>, String> {
    let items: Vec<LongEncryptedRecord> = encrypted
        .into_iter()
        .map(LongEncryptedRecord::from)
        .collect();
    let mut rng = rand::rng();
    let keys: crate::keys::SessionKeys = (*session_keys).into();
    let mut batch = EncryptedBatch::new(items, keys).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch
        .into_items()
        .into_iter()
        .map(WASMLongRecordEncrypted::from)
        .collect())
}

/// Batch transcrypt encrypted JSON values.
#[cfg(all(feature = "json", feature = "elgamal3"))]
#[wasm_bindgen(js_name = transcryptJSONBatch)]
pub fn wasm_transcrypt_json_batch(
    encrypted: Vec<WASMEncryptedPEPJSONValue>,
    info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMEncryptedPEPJSONValue>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    let mut batch = EncryptedBatch::new(items).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch
        .into_items()
        .into_iter()
        .map(WASMEncryptedPEPJSONValue)
        .collect())
}

#[cfg(all(feature = "json", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = transcryptJSONBatch)]
pub fn wasm_transcrypt_json_batch(
    encrypted: Vec<WASMEncryptedPEPJSONValue>,
    info: &WASMTranscryptionInfo,
    session_keys: &WASMSessionKeys,
) -> Result<Vec<WASMEncryptedPEPJSONValue>, String> {
    let items: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    let mut rng = rand::rng();
    let keys: crate::keys::SessionKeys = (*session_keys).into();
    let mut batch = EncryptedBatch::new(items, keys).map_err(|e| e.to_string())?;
    batch
        .transcrypt(&info.0, &mut rng)
        .map_err(|e| e.to_string())?;
    Ok(batch
        .into_items()
        .into_iter()
        .map(WASMEncryptedPEPJSONValue)
        .collect())
}
