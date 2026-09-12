#[cfg(feature = "json")]
use crate::data::json::{WASMEncryptedPEPJSONValue, WASMPEPJSONValue};
#[cfg(feature = "long")]
use crate::data::long::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};
#[cfg(feature = "long")]
use crate::data::records::{WASMLongRecord, WASMLongRecordEncrypted};
use crate::data::records::{WASMRecord, WASMRecordEncrypted};
use crate::data::simple::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::factors::types::WASMTranscryptionInfo;
use crate::keys::types::WASMSessionKeys;
#[cfg(feature = "offline")]
use crate::keys::types::{WASMAttributeGlobalPublicKey, WASMPseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::{WASMAttributeGlobalSecretKey, WASMPseudonymGlobalSecretKey};
use crate::keys::types::{
    WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey, WASMPseudonymSessionPublicKey,
    WASMPseudonymSessionSecretKey,
};
use crate::macros::{wasm_global_crypt_fns, wasm_session_crypt_fns};
#[cfg(all(feature = "offline", feature = "insecure"))]
use libpep::client::decrypt_global;
#[cfg(feature = "offline")]
use libpep::client::encrypt_global;
use libpep::client::{decrypt, encrypt};
use libpep::factors::TranscryptionInfo;
#[cfg(feature = "offline")]
use libpep::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use libpep::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use libpep::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey, SessionKeys,
};
use libpep::transcryptor::transcrypt;
use wasm_bindgen::prelude::*;

wasm_session_crypt_fns!(
    fns("encryptPseudonym" wasm_encrypt_pseudonym, "decryptPseudonym" wasm_decrypt_pseudonym)
        for WASMPseudonym => WASMEncryptedPseudonym,
        key(WASMPseudonymSessionPublicKey => PseudonymSessionPublicKey, WASMPseudonymSessionSecretKey => PseudonymSessionSecretKey);
    fns("encryptAttribute" wasm_encrypt_attribute, "decryptAttribute" wasm_decrypt_attribute)
        for WASMAttribute => WASMEncryptedAttribute,
        key(WASMAttributeSessionPublicKey => AttributeSessionPublicKey, WASMAttributeSessionSecretKey => AttributeSessionSecretKey);
    #[cfg(feature = "long")]
    fns("encryptLongPseudonym" wasm_encrypt_long_pseudonym, "decryptLongPseudonym" wasm_decrypt_long_pseudonym)
        for WASMLongPseudonym => WASMLongEncryptedPseudonym,
        key(WASMPseudonymSessionPublicKey => PseudonymSessionPublicKey, WASMPseudonymSessionSecretKey => PseudonymSessionSecretKey);
    #[cfg(feature = "long")]
    fns("encryptLongAttribute" wasm_encrypt_long_attribute, "decryptLongAttribute" wasm_decrypt_long_attribute)
        for WASMLongAttribute => WASMLongEncryptedAttribute,
        key(WASMAttributeSessionPublicKey => AttributeSessionPublicKey, WASMAttributeSessionSecretKey => AttributeSessionSecretKey);
);

// ============================================================================
// Record Functions
// ============================================================================

/// Encrypt a Record using session keys.
#[wasm_bindgen(js_name = encryptRecord)]
pub fn wasm_encrypt_record(record: WASMRecord, keys: &WASMSessionKeys) -> WASMRecordEncrypted {
    let mut rng = rand::rng();
    use libpep::data::records::Record;
    use libpep::data::traits::Encryptable;
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
    use libpep::data::records::EncryptedRecord;
    use libpep::data::traits::Encrypted;
    let session_keys: SessionKeys = (*keys).into();
    let rust_encrypted: EncryptedRecord = encrypted.into();
    rust_encrypted.decrypt(&session_keys).map(|r| r.into())
}

/// Decrypt an encrypted Record using session keys.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = decryptRecord)]
pub fn wasm_decrypt_record(encrypted: WASMRecordEncrypted, keys: &WASMSessionKeys) -> WASMRecord {
    use libpep::data::records::EncryptedRecord;
    use libpep::data::traits::Encrypted;
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
    use libpep::data::records::EncryptedRecord;
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
    use libpep::data::records::LongRecord;
    use libpep::data::traits::Encryptable;
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
    use libpep::data::records::LongEncryptedRecord;
    use libpep::data::traits::Encrypted;
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
    use libpep::data::records::LongEncryptedRecord;
    use libpep::data::traits::Encrypted;
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
    use libpep::data::records::LongEncryptedRecord;
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
    use libpep::data::traits::Encryptable;
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
    use libpep::data::traits::Encrypted;
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
    use libpep::data::traits::Encrypted;
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

wasm_global_crypt_fns!(
    fns("encryptPseudonymGlobal" wasm_encrypt_pseudonym_global, "decryptPseudonymGlobal" wasm_decrypt_pseudonym_global)
        for WASMPseudonym => WASMEncryptedPseudonym,
        key(WASMPseudonymGlobalPublicKey => PseudonymGlobalPublicKey, WASMPseudonymGlobalSecretKey => PseudonymGlobalSecretKey);
    fns("encryptAttributeGlobal" wasm_encrypt_attribute_global, "decryptAttributeGlobal" wasm_decrypt_attribute_global)
        for WASMAttribute => WASMEncryptedAttribute,
        key(WASMAttributeGlobalPublicKey => AttributeGlobalPublicKey, WASMAttributeGlobalSecretKey => AttributeGlobalSecretKey);
);

/// Encrypt a long pseudonym using a global public key (offline encryption).
#[cfg(all(feature = "offline", feature = "long"))]
#[wasm_bindgen(js_name = encryptLongPseudonymGlobal)]
pub fn wasm_encrypt_long_pseudonym_global(
    m: &WASMLongPseudonym,
    public_key: &WASMPseudonymGlobalPublicKey,
) -> WASMLongEncryptedPseudonym {
    let mut rng = rand::rng();
    let key = PseudonymGlobalPublicKey::from(*public_key.0);
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
    let key = PseudonymGlobalSecretKey::from(*secret_key.0);
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
    let key = PseudonymGlobalSecretKey::from(*secret_key.0);
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
    let key = AttributeGlobalPublicKey::from(*public_key.0);
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
    let key = AttributeGlobalSecretKey::from(*secret_key.0);
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
    let key = AttributeGlobalSecretKey::from(*secret_key.0);
    decrypt_global(&v.0, &key).into()
}
