//! Global-key based encryption and decryption operations for JSON values.
//!
//! These operations can be used when encryption happens offline and no session key is available,
//! or when using a session key may leak information.

#[cfg(feature = "insecure")]
use super::data::JsonError;
use super::data::{EncryptedPEPJSONValue, PEPJSONValue};
use crate::core::keys::GlobalPublicKeys;
#[cfg(feature = "insecure")]
use crate::core::keys::GlobalSecretKeys;
#[cfg(feature = "insecure")]
use crate::core::long::offline::{decrypt_long_attribute_global, decrypt_long_pseudonym_global};
use crate::core::long::offline::{encrypt_long_attribute_global, encrypt_long_pseudonym_global};
#[cfg(feature = "insecure")]
use crate::core::offline::decrypt_attribute_global;
use crate::core::offline::encrypt_attribute_global;
use rand_core::{CryptoRng, RngCore};

/// Encrypt a PEPJSONValue using global keys.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
pub fn encrypt_json_global<R: RngCore + CryptoRng>(
    value: &PEPJSONValue,
    global_keys: &GlobalPublicKeys,
    rng: &mut R,
) -> EncryptedPEPJSONValue {
    match value {
        PEPJSONValue::Null => EncryptedPEPJSONValue::Null,
        PEPJSONValue::Bool(attr) => {
            let encrypted = encrypt_attribute_global(attr, &global_keys.attribute, rng);
            EncryptedPEPJSONValue::Bool(encrypted)
        }
        PEPJSONValue::Number(attr) => {
            let encrypted = encrypt_attribute_global(attr, &global_keys.attribute, rng);
            EncryptedPEPJSONValue::Number(encrypted)
        }
        PEPJSONValue::String(long_attr) => {
            let encrypted = encrypt_long_attribute_global(long_attr, &global_keys.attribute, rng);
            EncryptedPEPJSONValue::String(encrypted)
        }
        PEPJSONValue::Pseudonym(long_pseudo) => {
            let encrypted = encrypt_long_pseudonym_global(long_pseudo, &global_keys.pseudonym, rng);
            EncryptedPEPJSONValue::Pseudonym(encrypted)
        }
        PEPJSONValue::Array(arr) => {
            let encrypted_arr = arr
                .iter()
                .map(|item| encrypt_json_global(item, global_keys, rng))
                .collect();
            EncryptedPEPJSONValue::Array(encrypted_arr)
        }
        PEPJSONValue::Object(obj) => {
            let encrypted_obj = obj
                .iter()
                .map(|(key, val)| (key.clone(), encrypt_json_global(val, global_keys, rng)))
                .collect();
            EncryptedPEPJSONValue::Object(encrypted_obj)
        }
    }
}

/// Decrypt an EncryptedPEPJSONValue using global secret keys.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
pub fn decrypt_json_global(
    encrypted: &EncryptedPEPJSONValue,
    global_secret_keys: &GlobalSecretKeys,
) -> Result<PEPJSONValue, JsonError> {
    match encrypted {
        EncryptedPEPJSONValue::Null => Ok(PEPJSONValue::Null),
        EncryptedPEPJSONValue::Bool(enc_attr) => {
            let attr = decrypt_attribute_global(enc_attr, &global_secret_keys.attribute)
                .ok_or_else(|| "Failed to decrypt bool attribute".to_string())?;
            Ok(PEPJSONValue::Bool(attr))
        }
        EncryptedPEPJSONValue::Number(enc_attr) => {
            let attr = decrypt_attribute_global(enc_attr, &global_secret_keys.attribute)
                .ok_or_else(|| "Failed to decrypt number attribute".to_string())?;
            Ok(PEPJSONValue::Number(attr))
        }
        EncryptedPEPJSONValue::String(enc_long_attr) => {
            let long_attr =
                decrypt_long_attribute_global(enc_long_attr, &global_secret_keys.attribute)
                    .ok_or_else(|| "Failed to decrypt string attribute".to_string())?;
            Ok(PEPJSONValue::String(long_attr))
        }
        EncryptedPEPJSONValue::Pseudonym(enc_long_pseudo) => {
            let long_pseudo =
                decrypt_long_pseudonym_global(enc_long_pseudo, &global_secret_keys.pseudonym)
                    .ok_or_else(|| "Failed to decrypt pseudonym".to_string())?;
            Ok(PEPJSONValue::Pseudonym(long_pseudo))
        }
        EncryptedPEPJSONValue::Array(arr) => {
            let decrypted_arr: Result<Vec<_>, _> = arr
                .iter()
                .map(|item| decrypt_json_global(item, global_secret_keys))
                .collect();
            Ok(PEPJSONValue::Array(decrypted_arr?))
        }
        EncryptedPEPJSONValue::Object(obj) => {
            let decrypted_obj: Result<_, _> = obj
                .iter()
                .map(|(key, val)| {
                    decrypt_json_global(val, global_secret_keys).map(|v| (key.clone(), v))
                })
                .collect();
            Ok(PEPJSONValue::Object(decrypted_obj?))
        }
    }
}

/// Decrypt an EncryptedPEPJSONValue using global secret keys.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
pub fn decrypt_json_global(
    encrypted: &EncryptedPEPJSONValue,
    global_secret_keys: &GlobalSecretKeys,
) -> Result<PEPJSONValue, JsonError> {
    match encrypted {
        EncryptedPEPJSONValue::Null => Ok(PEPJSONValue::Null),
        EncryptedPEPJSONValue::Bool(enc_attr) => {
            let attr = decrypt_attribute_global(enc_attr, &global_secret_keys.attribute);
            Ok(PEPJSONValue::Bool(attr))
        }
        EncryptedPEPJSONValue::Number(enc_attr) => {
            let attr = decrypt_attribute_global(enc_attr, &global_secret_keys.attribute);
            Ok(PEPJSONValue::Number(attr))
        }
        EncryptedPEPJSONValue::String(enc_long_attr) => {
            let long_attr =
                decrypt_long_attribute_global(enc_long_attr, &global_secret_keys.attribute);
            Ok(PEPJSONValue::String(long_attr))
        }
        EncryptedPEPJSONValue::Pseudonym(enc_long_pseudo) => {
            let long_pseudo =
                decrypt_long_pseudonym_global(enc_long_pseudo, &global_secret_keys.pseudonym);
            Ok(PEPJSONValue::Pseudonym(long_pseudo))
        }
        EncryptedPEPJSONValue::Array(arr) => {
            let decrypted_arr: Result<Vec<_>, _> = arr
                .iter()
                .map(|item| decrypt_json_global(item, global_secret_keys))
                .collect();
            Ok(PEPJSONValue::Array(decrypted_arr?))
        }
        EncryptedPEPJSONValue::Object(obj) => {
            let decrypted_obj: Result<_, _> = obj
                .iter()
                .map(|(key, val)| {
                    decrypt_json_global(val, global_secret_keys).map(|v| (key.clone(), v))
                })
                .collect();
            Ok(PEPJSONValue::Object(decrypted_obj?))
        }
    }
}
