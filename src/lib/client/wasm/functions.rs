#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::client::decrypt_global;
#[cfg(feature = "offline")]
use crate::client::encrypt_global;
use crate::client::{decrypt, encrypt};
#[cfg(feature = "json")]
use crate::data::wasm::json::{WASMEncryptedPEPJSONValue, WASMPEPJSONValue};
#[cfg(feature = "long")]
use crate::data::wasm::long::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};
#[cfg(feature = "long")]
use crate::data::wasm::records::{WASMLongRecord, WASMLongRecordEncrypted};
use crate::data::wasm::records::{WASMRecord, WASMRecordEncrypted};
use crate::data::wasm::simple::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::factors::wasm::contexts::WASMTranscryptionInfo;
use crate::factors::TranscryptionInfo;
use crate::keys::wasm::types::WASMSessionKeys;
#[cfg(feature = "offline")]
use crate::keys::wasm::types::{WASMAttributeGlobalPublicKey, WASMPseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::wasm::types::{WASMAttributeGlobalSecretKey, WASMPseudonymGlobalSecretKey};
use crate::keys::wasm::types::{
    WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey, WASMPseudonymSessionPublicKey,
    WASMPseudonymSessionSecretKey,
};
#[cfg(feature = "offline")]
use crate::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey, SessionKeys,
};
use crate::transcryptor::transcrypt;
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

// ============================================================================
// Record Functions
// ============================================================================

/// Encrypt a Record using session keys.
#[wasm_bindgen(js_name = encryptRecord)]
pub fn wasm_encrypt_record(record: WASMRecord, keys: &WASMSessionKeys) -> WASMRecordEncrypted {
    let mut rng = rand::rng();
    use crate::data::records::Record;
    use crate::data::traits::Encryptable;
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
    use crate::data::records::EncryptedRecord;
    use crate::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    let rust_encrypted: EncryptedRecord = encrypted.into();
    rust_encrypted.decrypt(&session_keys).map(|r| r.into())
}

/// Decrypt an encrypted Record using session keys.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptRecord)]
pub fn wasm_decrypt_record(encrypted: WASMRecordEncrypted, keys: &WASMSessionKeys) -> WASMRecord {
    use crate::data::records::EncryptedRecord;
    use crate::data::traits::Encrypted;
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
    use crate::data::records::EncryptedRecord;
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
    use crate::data::records::LongRecord;
    use crate::data::traits::Encryptable;
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
    use crate::data::records::LongEncryptedRecord;
    use crate::data::traits::Encrypted;
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
    use crate::data::records::LongEncryptedRecord;
    use crate::data::traits::Encrypted;
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
    use crate::data::records::LongEncryptedRecord;
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
    use crate::data::traits::Encryptable;
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
    use crate::data::traits::Encrypted;
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
    use crate::data::traits::Encrypted;
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
