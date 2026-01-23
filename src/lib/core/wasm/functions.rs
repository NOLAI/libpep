use super::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymRekeyFactor, WASMPseudonymizationInfo,
    WASMTranscryptionInfo,
};
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
#[cfg(feature = "batch")]
use crate::core::batch::{
    decrypt_batch, encrypt_batch, pseudonymize_batch, rekey_batch, transcrypt_batch,
};
use crate::core::data::records::EncryptedRecord;
use crate::core::data::records::LongEncryptedRecord;
use crate::core::factors::TranscryptionInfo;
use crate::core::factors::{AttributeRekeyInfo, PseudonymizationInfo, RerandomizeFactor};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::core::functions::decrypt_global;
#[cfg(feature = "offline")]
use crate::core::functions::encrypt_global;
use crate::core::functions::{
    decrypt, encrypt, pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt,
};
#[cfg(feature = "offline")]
use crate::core::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::core::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::core::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey, SessionKeys,
};
#[cfg(feature = "json")]
use crate::core::wasm::data::json::{WASMEncryptedPEPJSONValue, WASMPEPJSONValue};
#[cfg(feature = "long")]
use crate::core::wasm::data::long::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};
#[cfg(feature = "long")]
use crate::core::wasm::data::records::{WASMLongRecord, WASMLongRecordEncrypted};
use crate::core::wasm::data::records::{WASMRecord, WASMRecordEncrypted};
use crate::core::wasm::data::simple::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::core::wasm::keys::types::WASMSessionKeys;
#[cfg(feature = "offline")]
use crate::core::wasm::keys::types::{WASMAttributeGlobalPublicKey, WASMPseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::core::wasm::keys::types::{WASMAttributeGlobalSecretKey, WASMPseudonymGlobalSecretKey};
use crate::core::wasm::keys::{
    WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey, WASMPseudonymSessionPublicKey,
    WASMPseudonymSessionSecretKey,
};
use wasm_bindgen::prelude::*;

/// Encrypt a pseudonym using a session public key.
#[wasm_bindgen(js_name = encryptPseudonym)]
pub fn wasm_encrypt_pseudonym(
    m: &WASMPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    encrypt(
        &m.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an encrypted pseudonym using a session secret key.
#[wasm_bindgen(js_name = decryptPseudonym)]
#[cfg(feature = "elgamal3")]
pub fn wasm_decrypt_pseudonym(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> Option<WASMPseudonym> {
    decrypt(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an encrypted pseudonym using a session secret key.
#[wasm_bindgen(js_name = decryptPseudonym)]
#[cfg(not(feature = "elgamal3"))]
pub fn wasm_decrypt_pseudonym(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> WASMPseudonym {
    decrypt(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Encrypt an attribute using a session public key.
#[wasm_bindgen(js_name = encryptAttribute)]
pub fn wasm_encrypt_attribute(
    m: &WASMAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    encrypt(
        &m.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an encrypted attribute using a session secret key.
#[wasm_bindgen(js_name = decryptAttribute)]
#[cfg(feature = "elgamal3")]
pub fn wasm_decrypt_attribute(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> Option<WASMAttribute> {
    decrypt(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an encrypted attribute using a session secret key.
#[wasm_bindgen(js_name = decryptAttribute)]
#[cfg(not(feature = "elgamal3"))]
pub fn wasm_decrypt_attribute(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> WASMAttribute {
    decrypt(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Pseudonymize an encrypted pseudonym from one domain/session to another.
#[wasm_bindgen(js_name = pseudonymize)]
pub fn wasm_pseudonymize(
    encrypted: &WASMEncryptedPseudonym,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> WASMEncryptedPseudonym {
    pseudonymize(
        &encrypted.0,
        &PseudonymizationInfo::from(pseudonymization_info),
    )
    .into()
}

/// Rekey an encrypted pseudonym from one session to another.
#[wasm_bindgen(js_name = rekeyPseudonym)]
pub fn wasm_rekey_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    rekey_info: &WASMPseudonymRekeyFactor,
) -> WASMEncryptedPseudonym {
    rekey(&encrypted.0, &rekey_info.0).into()
}

/// Rekey an encrypted attribute from one session to another.
#[wasm_bindgen(js_name = rekeyAttribute)]
pub fn wasm_rekey_attribute(
    encrypted: &WASMEncryptedAttribute,
    rekey_info: &WASMAttributeRekeyInfo,
) -> WASMEncryptedAttribute {
    rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)).into()
}

/// Transcrypt an encrypted pseudonym from one domain/session to another.
#[wasm_bindgen(js_name = transcryptPseudonym)]
pub fn wasm_transcrypt_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMEncryptedPseudonym {
    transcrypt(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}

/// Transcrypt an encrypted attribute from one session to another.
#[wasm_bindgen(js_name = transcryptAttribute)]
pub fn wasm_transcrypt_attribute(
    encrypted: &WASMEncryptedAttribute,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMEncryptedAttribute {
    transcrypt(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(v: &WASMEncryptedPseudonym) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize an encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(
    v: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize an encrypted attribute.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttribute)]
pub fn wasm_rerandomize_encrypted_attribute(v: &WASMEncryptedAttribute) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize an encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttribute)]
pub fn wasm_rerandomize_encrypted_attribute(
    v: &WASMEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    v: &WASMEncryptedPseudonym,
    r: &WASMScalarNonZero,
) -> WASMEncryptedPseudonym {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    v: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMEncryptedPseudonym {
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttributeKnown)]
pub fn wasm_rerandomize_encrypted_attribute_known(
    v: &WASMEncryptedAttribute,
    r: &WASMScalarNonZero,
) -> WASMEncryptedAttribute {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeEncryptedAttributeKnown)]
pub fn wasm_rerandomize_encrypted_attribute_known(
    v: &WASMEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMEncryptedAttribute {
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}
// ============================================================================
// Long Pseudonym and Attribute Functions
// ============================================================================

/// Encrypt a long pseudonym using a session public key.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = encryptLongPseudonym)]
pub fn wasm_encrypt_long_pseudonym(
    m: &WASMLongPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    encrypt(
        &m.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an encrypted long pseudonym using a session secret key.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptLongPseudonym)]
pub fn wasm_decrypt_long_pseudonym(
    v: &WASMLongEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> Option<WASMLongPseudonym> {
    decrypt(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an encrypted long pseudonym using a session secret key.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptLongPseudonym)]
pub fn wasm_decrypt_long_pseudonym(
    v: &WASMLongEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> WASMLongPseudonym {
    decrypt(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Encrypt a long attribute using a session public key.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = encryptLongAttribute)]
pub fn wasm_encrypt_long_attribute(
    m: &WASMLongAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    encrypt(
        &m.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an encrypted long attribute using a session secret key.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptLongAttribute)]
pub fn wasm_decrypt_long_attribute(
    v: &WASMLongEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> Option<WASMLongAttribute> {
    decrypt(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an encrypted long attribute using a session secret key.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptLongAttribute)]
pub fn wasm_decrypt_long_attribute(
    v: &WASMLongEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> WASMLongAttribute {
    decrypt(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Pseudonymize a long encrypted pseudonym from one domain/session to another.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = pseudonymizeLong)]
pub fn wasm_pseudonymize_long(
    encrypted: &WASMLongEncryptedPseudonym,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> WASMLongEncryptedPseudonym {
    pseudonymize(
        &encrypted.0,
        &PseudonymizationInfo::from(pseudonymization_info),
    )
    .into()
}

/// Rekey a long encrypted pseudonym from one session to another.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = rekeyLongPseudonym)]
pub fn wasm_rekey_long_pseudonym(
    encrypted: &WASMLongEncryptedPseudonym,
    rekey_info: &WASMPseudonymRekeyFactor,
) -> WASMLongEncryptedPseudonym {
    rekey(&encrypted.0, &rekey_info.0).into()
}

/// Rekey a long encrypted attribute from one session to another.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = rekeyLongAttribute)]
pub fn wasm_rekey_long_attribute(
    encrypted: &WASMLongEncryptedAttribute,
    rekey_info: &WASMAttributeRekeyInfo,
) -> WASMLongEncryptedAttribute {
    rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)).into()
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonym)]
pub fn wasm_rerandomize_long_encrypted_pseudonym(
    v: &WASMLongEncryptedPseudonym,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonym)]
pub fn wasm_rerandomize_long_encrypted_pseudonym(
    v: &WASMLongEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize a long encrypted attribute.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttribute)]
pub fn wasm_rerandomize_long_encrypted_attribute(
    v: &WASMLongEncryptedAttribute,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize a long encrypted attribute.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttribute)]
pub fn wasm_rerandomize_long_encrypted_attribute(
    v: &WASMLongEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize(&v.0, &pk, &mut rng).into()
}

/// Rerandomize a long encrypted pseudonym using a known factor.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_long_encrypted_pseudonym_known(
    v: &WASMLongEncryptedPseudonym,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedPseudonym {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize a long encrypted pseudonym using a known factor.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedPseudonymKnown)]
pub fn wasm_rerandomize_long_encrypted_pseudonym_known(
    v: &WASMLongEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedPseudonym {
    let pk = PseudonymSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize a long encrypted attribute using a known factor.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttributeKnown)]
pub fn wasm_rerandomize_long_encrypted_attribute_known(
    v: &WASMLongEncryptedAttribute,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedAttribute {
    rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize a long encrypted attribute using a known factor.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = rerandomizeLongEncryptedAttributeKnown)]
pub fn wasm_rerandomize_long_encrypted_attribute_known(
    v: &WASMLongEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
    r: &WASMScalarNonZero,
) -> WASMLongEncryptedAttribute {
    let pk = AttributeSessionPublicKey(public_key.0 .0);
    rerandomize_known(&v.0, &pk, &RerandomizeFactor(r.0)).into()
}

// ============================================================================
// Record Functions
// ============================================================================

/// Encrypt a Record using session keys.
#[wasm_bindgen(js_name = encryptRecord)]
pub fn wasm_encrypt_record(record: WASMRecord, keys: &WASMSessionKeys) -> WASMRecordEncrypted {
    let mut rng = rand::rng();
    use crate::core::data::records::Record;
    use crate::core::data::traits::Encryptable;
    let session_keys: SessionKeys = (*keys).into();
    let rust_record: Record = record.into();
    rust_record.encrypt(&session_keys, &mut rng).into()
}

/// Decrypt an encrypted Record using session keys.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = decryptRecord)]
pub fn wasm_decrypt_record(
    encrypted: WASMRecordEncrypted,
    keys: &WASMSessionKeys,
) -> Option<WASMRecord> {
    use crate::core::data::records::EncryptedRecord;
    use crate::core::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    let rust_encrypted: EncryptedRecord = encrypted.into();
    rust_encrypted.decrypt(&session_keys).map(|r| r.into())
}

/// Decrypt an encrypted Record using session keys.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptRecord)]
pub fn wasm_decrypt_record(encrypted: WASMRecordEncrypted, keys: &WASMSessionKeys) -> WASMRecord {
    use crate::core::data::records::EncryptedRecord;
    use crate::core::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    let rust_encrypted: EncryptedRecord = encrypted.into();
    rust_encrypted.decrypt(&session_keys).into()
}

/// Transcrypt an encrypted Record from one context to another.
#[wasm_bindgen(js_name = transcryptRecord)]
pub fn wasm_transcrypt_record(
    encrypted: WASMRecordEncrypted,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMRecordEncrypted {
    use crate::core::data::records::EncryptedRecord;
    let rust_encrypted: EncryptedRecord = encrypted.into();
    transcrypt(
        &rust_encrypted,
        &TranscryptionInfo::from(transcryption_info),
    )
    .into()
}

/// Encrypt a LongRecord using session keys.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = encryptLongRecord)]
pub fn wasm_encrypt_long_record(
    record: WASMLongRecord,
    keys: &WASMSessionKeys,
) -> WASMLongRecordEncrypted {
    let mut rng = rand::rng();
    use crate::core::data::records::LongRecord;
    use crate::core::data::traits::Encryptable;
    let session_keys: SessionKeys = (*keys).into();
    let rust_record: LongRecord = record.into();
    rust_record.encrypt(&session_keys, &mut rng).into()
}

/// Decrypt an encrypted LongRecord using session keys.
#[cfg(all(feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptLongRecord)]
pub fn wasm_decrypt_long_record(
    encrypted: WASMLongRecordEncrypted,
    keys: &WASMSessionKeys,
) -> Option<WASMLongRecord> {
    use crate::core::data::records::LongEncryptedRecord;
    use crate::core::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    let rust_encrypted: LongEncryptedRecord = encrypted.into();
    rust_encrypted.decrypt(&session_keys).map(|r| r.into())
}

/// Decrypt an encrypted LongRecord using session keys.
#[cfg(all(feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptLongRecord)]
pub fn wasm_decrypt_long_record(
    encrypted: WASMLongRecordEncrypted,
    keys: &WASMSessionKeys,
) -> WASMLongRecord {
    use crate::core::data::records::LongEncryptedRecord;
    use crate::core::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    let rust_encrypted: LongEncryptedRecord = encrypted.into();
    rust_encrypted.decrypt(&session_keys).into()
}

/// Transcrypt an encrypted LongRecord from one context to another.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = transcryptLongRecord)]
pub fn wasm_transcrypt_long_record(
    encrypted: WASMLongRecordEncrypted,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMLongRecordEncrypted {
    use crate::core::data::records::LongEncryptedRecord;
    let rust_encrypted: LongEncryptedRecord = encrypted.into();
    transcrypt(
        &rust_encrypted,
        &TranscryptionInfo::from(transcryption_info),
    )
    .into()
}

// ============================================================================
// JSON Functions
// ============================================================================

/// Encrypt a PEPJSONValue using session keys.
#[cfg(feature = "json")]
#[wasm_bindgen(js_name = encryptJSON)]
pub fn wasm_encrypt_json(
    json: &WASMPEPJSONValue,
    keys: &WASMSessionKeys,
) -> WASMEncryptedPEPJSONValue {
    let mut rng = rand::rng();
    use crate::core::data::traits::Encryptable;
    let session_keys: SessionKeys = (*keys).into();
    WASMEncryptedPEPJSONValue(json.0.encrypt(&session_keys, &mut rng))
}

/// Decrypt an encrypted PEPJSONValue using session keys.
#[cfg(all(feature = "json", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptJSON)]
pub fn wasm_decrypt_json(
    encrypted: &WASMEncryptedPEPJSONValue,
    keys: &WASMSessionKeys,
) -> Option<WASMPEPJSONValue> {
    use crate::core::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    encrypted.0.decrypt(&session_keys).map(WASMPEPJSONValue)
}

/// Decrypt an encrypted PEPJSONValue using session keys.
#[cfg(all(feature = "json", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptJSON)]
pub fn wasm_decrypt_json(
    encrypted: &WASMEncryptedPEPJSONValue,
    keys: &WASMSessionKeys,
) -> WASMPEPJSONValue {
    use crate::core::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    WASMPEPJSONValue(encrypted.0.decrypt(&session_keys))
}

/// Transcrypt an encrypted PEPJSONValue from one context to another.
#[cfg(feature = "json")]
#[wasm_bindgen(js_name = transcryptJSON)]
pub fn wasm_transcrypt_json(
    encrypted: &WASMEncryptedPEPJSONValue,
    transcryption_info: &WASMTranscryptionInfo,
) -> WASMEncryptedPEPJSONValue {
    WASMEncryptedPEPJSONValue(transcrypt(
        &encrypted.0,
        &TranscryptionInfo::from(transcryption_info),
    ))
}

// ============================================================================
// Offline Encryption Functions
// ============================================================================

/// Encrypt a pseudonym using a global public key (offline encryption).
#[cfg(feature = "offline")]
#[wasm_bindgen(js_name = encryptPseudonymGlobal)]
pub fn wasm_encrypt_pseudonym_global(
    m: &WASMPseudonym,
    public_key: &WASMPseudonymGlobalPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::rng();
    let key = PseudonymGlobalPublicKey(public_key.0 .0);
    encrypt_global(&m.0, &key, &mut rng).into()
}

/// Decrypt an encrypted pseudonym using a global secret key (offline decryption).
#[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptPseudonymGlobal)]
pub fn wasm_decrypt_pseudonym_global(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymGlobalSecretKey,
) -> Option<WASMPseudonym> {
    let key = PseudonymGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).map(|x| x.into())
}

/// Decrypt an encrypted pseudonym using a global secret key (offline decryption).
#[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptPseudonymGlobal)]
pub fn wasm_decrypt_pseudonym_global(
    v: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymGlobalSecretKey,
) -> WASMPseudonym {
    let key = PseudonymGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).into()
}

/// Encrypt an attribute using a global public key (offline encryption).
#[cfg(feature = "offline")]
#[wasm_bindgen(js_name = encryptAttributeGlobal)]
pub fn wasm_encrypt_attribute_global(
    m: &WASMAttribute,
    public_key: &WASMAttributeGlobalPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::rng();
    let key = AttributeGlobalPublicKey(public_key.0 .0);
    encrypt_global(&m.0, &key, &mut rng).into()
}

/// Decrypt an encrypted attribute using a global secret key (offline decryption).
#[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptAttributeGlobal)]
pub fn wasm_decrypt_attribute_global(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeGlobalSecretKey,
) -> Option<WASMAttribute> {
    let key = AttributeGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).map(|x| x.into())
}

/// Decrypt an encrypted attribute using a global secret key (offline decryption).
#[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptAttributeGlobal)]
pub fn wasm_decrypt_attribute_global(
    v: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeGlobalSecretKey,
) -> WASMAttribute {
    let key = AttributeGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).into()
}

/// Encrypt a long pseudonym using a global public key (offline encryption).
#[cfg(all(feature = "offline", feature = "long"))]
#[wasm_bindgen(js_name = encryptLongPseudonymGlobal)]
pub fn wasm_encrypt_long_pseudonym_global(
    m: &WASMLongPseudonym,
    public_key: &WASMPseudonymGlobalPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    let key = PseudonymGlobalPublicKey(public_key.0 .0);
    encrypt_global(&m.0, &key, &mut rng).into()
}

/// Decrypt an encrypted long pseudonym using a global secret key (offline decryption).
#[cfg(all(
    feature = "offline",
    feature = "insecure",
    feature = "long",
    feature = "elgamal3"
))]
#[wasm_bindgen(js_name = decryptLongPseudonymGlobal)]
pub fn wasm_decrypt_long_pseudonym_global(
    v: &WASMLongEncryptedPseudonym,
    secret_key: &WASMPseudonymGlobalSecretKey,
) -> Option<WASMLongPseudonym> {
    let key = PseudonymGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).map(|x| x.into())
}

/// Decrypt an encrypted long pseudonym using a global secret key (offline decryption).
#[cfg(all(
    feature = "offline",
    feature = "insecure",
    feature = "long",
    not(feature = "elgamal3")
))]
#[wasm_bindgen(js_name = decryptLongPseudonymGlobal)]
pub fn wasm_decrypt_long_pseudonym_global(
    v: &WASMLongEncryptedPseudonym,
    secret_key: &WASMPseudonymGlobalSecretKey,
) -> WASMLongPseudonym {
    let key = PseudonymGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).into()
}

/// Encrypt a long attribute using a global public key (offline encryption).
#[cfg(all(feature = "offline", feature = "long"))]
#[wasm_bindgen(js_name = encryptLongAttributeGlobal)]
pub fn wasm_encrypt_long_attribute_global(
    m: &WASMLongAttribute,
    public_key: &WASMAttributeGlobalPublicKey,
) -> WASMLongEncryptedAttribute {
    let mut rng = rand::rng();
    let key = AttributeGlobalPublicKey(public_key.0 .0);
    encrypt_global(&m.0, &key, &mut rng).into()
}

/// Decrypt an encrypted long attribute using a global secret key (offline decryption).
#[cfg(all(
    feature = "offline",
    feature = "insecure",
    feature = "long",
    feature = "elgamal3"
))]
#[wasm_bindgen(js_name = decryptLongAttributeGlobal)]
pub fn wasm_decrypt_long_attribute_global(
    v: &WASMLongEncryptedAttribute,
    secret_key: &WASMAttributeGlobalSecretKey,
) -> Option<WASMLongAttribute> {
    let key = AttributeGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).map(|x| x.into())
}

/// Decrypt an encrypted long attribute using a global secret key (offline decryption).
#[cfg(all(
    feature = "offline",
    feature = "insecure",
    feature = "long",
    not(feature = "elgamal3")
))]
#[wasm_bindgen(js_name = decryptLongAttributeGlobal)]
pub fn wasm_decrypt_long_attribute_global(
    v: &WASMLongEncryptedAttribute,
    secret_key: &WASMAttributeGlobalSecretKey,
) -> WASMLongAttribute {
    let key = AttributeGlobalSecretKey(secret_key.0 .0);
    decrypt_global(&v.0, &key).into()
}

// ============================================================================
// Batch Functions
// ============================================================================

/// Batch encrypt pseudonyms using a session public key.
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = encryptPseudonymBatch)]
pub fn wasm_encrypt_pseudonym_batch(
    messages: Vec<WASMPseudonym>,
    key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMEncryptedPseudonym>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &PseudonymSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted pseudonyms using a session secret key.
#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptPseudonymBatch)]
pub fn wasm_decrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted pseudonyms using a session secret key.
#[cfg(all(feature = "batch", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptPseudonymBatch)]
pub fn wasm_decrypt_pseudonym_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMPseudonym).collect())
        .map_err(|e| e.to_string())
}

/// Batch encrypt attributes using a session public key.
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = encryptAttributeBatch)]
pub fn wasm_encrypt_attribute_batch(
    messages: Vec<WASMAttribute>,
    key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMEncryptedAttribute>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &AttributeSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted attributes using a session secret key.
#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptAttributeBatch)]
pub fn wasm_decrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted attributes using a session secret key.
#[cfg(all(feature = "batch", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptAttributeBatch)]
pub fn wasm_decrypt_attribute_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMAttribute).collect())
        .map_err(|e| e.to_string())
}

/// Batch encrypt long pseudonyms using a session public key.
#[cfg(all(feature = "batch", feature = "long"))]
#[wasm_bindgen(js_name = encryptLongPseudonymBatch)]
pub fn wasm_encrypt_long_pseudonym_batch(
    messages: Vec<WASMLongPseudonym>,
    key: &WASMPseudonymSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedPseudonym>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0.clone()).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &PseudonymSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long pseudonyms using a session secret key.
#[cfg(all(feature = "batch", feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptLongPseudonymBatch)]
pub fn wasm_decrypt_long_pseudonym_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMLongPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long pseudonyms using a session secret key.
#[cfg(all(feature = "batch", feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptLongPseudonymBatch)]
pub fn wasm_decrypt_long_pseudonym_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    key: &WASMPseudonymSessionSecretKey,
) -> Result<Vec<WASMLongPseudonym>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &PseudonymSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMLongPseudonym).collect())
        .map_err(|e| e.to_string())
}

/// Batch encrypt long attributes using a session public key.
#[cfg(all(feature = "batch", feature = "long"))]
#[wasm_bindgen(js_name = encryptLongAttributeBatch)]
pub fn wasm_encrypt_long_attribute_batch(
    messages: Vec<WASMLongAttribute>,
    key: &WASMAttributeSessionPublicKey,
) -> Result<Vec<WASMLongEncryptedAttribute>, String> {
    let rust_msgs: Vec<_> = messages.iter().map(|m| m.0.clone()).collect();
    let mut rng = rand::rng();
    encrypt_batch(
        &rust_msgs,
        &AttributeSessionPublicKey::from(key.0 .0),
        &mut rng,
    )
    .map(|encrypted| encrypted.into_iter().map(|e| e.into()).collect())
    .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long attributes using a session secret key.
#[cfg(all(feature = "batch", feature = "long", feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptLongAttributeBatch)]
pub fn wasm_decrypt_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMLongAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(|d| d.into()).collect())
        .map_err(|e| e.to_string())
}

/// Batch decrypt encrypted long attributes using a session secret key.
#[cfg(all(feature = "batch", feature = "long", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = decryptLongAttributeBatch)]
pub fn wasm_decrypt_long_attribute_batch(
    encrypted: Vec<WASMLongEncryptedAttribute>,
    key: &WASMAttributeSessionSecretKey,
) -> Result<Vec<WASMLongAttribute>, String> {
    let rust_enc: Vec<_> = encrypted.iter().map(|e| e.0.clone()).collect();
    decrypt_batch(&rust_enc, &AttributeSessionSecretKey::from(key.0 .0))
        .map(|decrypted| decrypted.into_iter().map(WASMLongAttribute).collect())
        .map_err(|e| e.to_string())
}

/// Batch pseudonymize encrypted pseudonyms.
#[cfg(feature = "batch")]
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
#[cfg(all(feature = "batch", feature = "long"))]
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
#[cfg(feature = "batch")]
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
#[cfg(all(feature = "batch", feature = "long"))]
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
#[cfg(feature = "batch")]
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
#[cfg(feature = "batch")]
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
#[cfg(feature = "batch")]
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
#[cfg(all(feature = "batch", feature = "long"))]
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
#[cfg(all(feature = "batch", feature = "json"))]
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
