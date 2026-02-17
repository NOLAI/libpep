//! Python bindings for batch transcryption operations.

use crate::client::{decrypt_batch, encrypt_batch};
use crate::data::py::records::PyEncryptedRecord;
#[cfg(feature = "long")]
use crate::data::py::records::PyLongEncryptedRecord;
use crate::data::py::simple::{
    PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym,
};
use crate::data::records::EncryptedRecord;
use crate::factors::py::contexts::{
    PyAttributeRekeyInfo, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use crate::factors::TranscryptionInfo;
use crate::factors::{AttributeRekeyInfo, PseudonymizationInfo};
use crate::keys::py::types::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey, PyGlobalPublicKeys, AttributeSessionKeys, PseudonymSessionKeys,
};
use crate::keys::types::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use crate::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::IntoPyObjectExt;

#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::client::decrypt_global;
#[cfg(feature = "offline")]
use crate::client::encrypt_global;
#[cfg(feature = "offline")]
use crate::keys::py::types::{PyAttributeGlobalPublicKey, PyPseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::py::types::{PyAttributeGlobalSecretKey, PyPseudonymGlobalSecretKey};
#[cfg(feature = "offline")]
use crate::keys::types::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};

#[cfg(feature = "long")]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "long")]
use crate::data::py::long::{
    PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym, PyLongPseudonym,
};
#[cfg(feature = "long")]
use crate::data::records::LongEncryptedRecord;

#[cfg(feature = "json")]
use crate::data::py::json::{PyPEPJSONValue, PyEncryptedPEPJSONValue};
use crate::keys::{GlobalPublicKeys, PseudonymSessionKeys, SessionKeys};

/// Polymorphic batch pseudonymization of a list of encrypted pseudonyms.
/// Works with both EncryptedPseudonym and LongEncryptedPseudonym.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[pyfunction]
#[pyo3(name = "pseudonymize_batch")]
pub fn py_pseudonymize_batch(
    encrypted: &Bound<PyAny>,
    pseudonymization_info: &PyPseudonymizationInfo,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let mut rng = rand::rng();
    let info = PseudonymizationInfo::from(pseudonymization_info);

    // Try Vec<EncryptedPseudonym>
    if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
        let mut enc: Vec<_> = eps.into_iter().map(|e| e.0).collect();
        let result = pseudonymize_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<PyEncryptedPseudonym> = result
            .into_vec()
            .into_iter()
            .map(PyEncryptedPseudonym)
            .collect();
        return py_result.into_py_any(py);
    }

    // Try Vec<LongEncryptedPseudonym>
    #[cfg(feature = "long")]
    if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
        let mut enc: Vec<LongEncryptedPseudonym> = leps.into_iter().map(|e| e.0).collect();
        let result = pseudonymize_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<PyLongEncryptedPseudonym> = result
            .into_vec()
            .into_iter()
            .map(PyLongEncryptedPseudonym)
            .collect();
        return py_result.into_py_any(py);
    }

    Err(PyTypeError::new_err(
        "pseudonymize_batch() requires Vec[EncryptedPseudonym] or Vec[LongEncryptedPseudonym]",
    ))
}

/// Polymorphic batch rekeying of a list of encrypted attributes.
/// Works with both EncryptedAttribute and LongEncryptedAttribute.
/// The order of the attributes is randomly shuffled to avoid linking them.
#[pyfunction]
#[pyo3(name = "rekey_batch")]
pub fn py_rekey_batch(
    encrypted: &Bound<PyAny>,
    rekey_info: &PyAttributeRekeyInfo,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let mut rng = rand::rng();
    let info = AttributeRekeyInfo::from(rekey_info);

    // Try Vec<EncryptedAttribute>
    if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
        let mut enc: Vec<_> = eas.into_iter().map(|e| e.0).collect();
        let result = rekey_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<PyEncryptedAttribute> = result
            .into_vec()
            .into_iter()
            .map(PyEncryptedAttribute)
            .collect();
        return py_result.into_py_any(py);
    }

    // Try Vec<LongEncryptedAttribute>
    #[cfg(feature = "long")]
    if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
        let mut enc: Vec<LongEncryptedAttribute> = leas.into_iter().map(|e| e.0).collect();
        let result = rekey_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<PyLongEncryptedAttribute> = result
            .into_vec()
            .into_iter()
            .map(PyLongEncryptedAttribute)
            .collect();
        return py_result.into_py_any(py);
    }

    Err(PyTypeError::new_err(
        "rekey_batch() requires Vec[EncryptedAttribute] or Vec[LongEncryptedAttribute]",
    ))
}

/// Polymorphic batch transcryption of a list of encrypted data.
/// Works with EncryptedRecord, LongEncryptedRecord, EncryptedPEPJSONValue, or tuples.
/// The order of items is randomly shuffled to avoid linking them.
///
/// # Errors
///
/// Raises a ValueError if the encrypted data do not all have the same structure.
#[pyfunction]
#[pyo3(name = "transcrypt_batch")]
pub fn py_transcrypt_batch(
    encrypted: &Bound<PyAny>,
    transcryption_info: &PyTranscryptionInfo,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let mut rng = rand::rng();
    let info = TranscryptionInfo::from(transcryption_info);

    // Try Vec<EncryptedRecord>
    if let Ok(recs) = encrypted.extract::<Vec<PyEncryptedRecord>>() {
        let mut enc: Vec<_> = recs.into_iter().map(|r| r.0).collect();
        let result = transcrypt_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<PyEncryptedRecord> = result
            .into_vec()
            .into_iter()
            .map(PyEncryptedRecord)
            .collect();
        return py_result.into_py_any(py);
    }

    // Try Vec<LongEncryptedRecord>
    #[cfg(feature = "long")]
    if let Ok(lrecs) = encrypted.extract::<Vec<PyLongEncryptedRecord>>() {
        let mut enc: Vec<LongEncryptedRecord> = lrecs.into_iter().map(|r| r.0).collect();
        let result = transcrypt_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<PyLongEncryptedRecord> = result
            .into_vec()
            .into_iter()
            .map(PyLongEncryptedRecord)
            .collect();
        return py_result.into_py_any(py);
    }

    // Try Vec<EncryptedPEPJSONValue>
    #[cfg(feature = "json")]
    if let Ok(jsons) = encrypted.extract::<Vec<PyEncryptedPEPJSONValue>>() {
        let mut enc: Vec<_> = jsons.into_iter().map(|j| j.0).collect();
        let result = transcrypt_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<PyEncryptedPEPJSONValue> = result
            .into_vec()
            .into_iter()
            .map(PyEncryptedPEPJSONValue)
            .collect();
        return py_result.into_py_any(py);
    }

    // Try Vec<(Vec<EncryptedPseudonym>, Vec<EncryptedAttribute>)>
    if let Ok(recs) =
        encrypted.extract::<Vec<(Vec<PyEncryptedPseudonym>, Vec<PyEncryptedAttribute>)>>()
    {
        let mut enc: Vec<_> = recs
            .into_iter()
            .map(|(ps, attrs)| {
                EncryptedRecord::new(
                    ps.into_iter().map(|p| p.0).collect(),
                    attrs.into_iter().map(|a| a.0).collect(),
                )
            })
            .collect();
        let result = transcrypt_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<(Vec<PyEncryptedPseudonym>, Vec<PyEncryptedAttribute>)> = result
            .into_vec()
            .into_iter()
            .map(|record| {
                (
                    record
                        .pseudonyms
                        .into_iter()
                        .map(PyEncryptedPseudonym)
                        .collect(),
                    record
                        .attributes
                        .into_iter()
                        .map(PyEncryptedAttribute)
                        .collect(),
                )
            })
            .collect();
        return py_result.into_py_any(py);
    }

    // Try Vec<(Vec<LongEncryptedPseudonym>, Vec<LongEncryptedAttribute>)>
    #[cfg(feature = "long")]
    if let Ok(lrecs) =
        encrypted.extract::<Vec<(Vec<PyLongEncryptedPseudonym>, Vec<PyLongEncryptedAttribute>)>>()
    {
        let mut enc: Vec<LongEncryptedRecord> = lrecs
            .into_iter()
            .map(|(ps, attrs)| {
                LongEncryptedRecord::new(
                    ps.into_iter().map(|p| p.0).collect(),
                    attrs.into_iter().map(|a| a.0).collect(),
                )
            })
            .collect();
        let result = transcrypt_batch(&mut enc, &info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        let py_result: Vec<(Vec<PyLongEncryptedPseudonym>, Vec<PyLongEncryptedAttribute>)> = result
            .into_vec()
            .into_iter()
            .map(|record| {
                (
                    record
                        .pseudonyms
                        .into_iter()
                        .map(PyLongEncryptedPseudonym)
                        .collect(),
                    record
                        .attributes
                        .into_iter()
                        .map(PyLongEncryptedAttribute)
                        .collect(),
                )
            })
            .collect();
        return py_result.into_py_any(py);
    }

    Err(PyTypeError::new_err(
        "transcrypt_batch() requires Vec[EncryptedRecord], Vec[LongEncryptedRecord], Vec[EncryptedPEPJSONValue], or tuple-based variants"
    ))
}

/// Polymorphic batch encryption.
/// Encrypts a list of unencrypted messages with a session public key.
#[pyfunction]
#[pyo3(name = "encrypt_batch")]
pub fn py_encrypt_batch(messages: &Bound<PyAny>, public_key: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = messages.py();
    let mut rng = rand::rng();

    // Try Vec<PyPseudonym> with PyPseudonymSessionPublicKey
    if let Ok(ps) = messages.extract::<Vec<PyPseudonym>>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
            let key = PseudonymSessionPublicKey::from(pk.0 .0);
            let rust_msgs: Vec<_> = ps.into_iter().map(|p| p.0).collect();

            // True Batch: Shuffles and encrypts
            let result = encrypt_batch(&rust_msgs, &key, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            let py_result: Vec<PyEncryptedPseudonym> = result.into_iter().map(PyEncryptedPseudonym).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyAttribute> with PyAttributeSessionPublicKey
    if let Ok(attrs) = messages.extract::<Vec<PyAttribute>>() {
        if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
            let key = AttributeSessionPublicKey::from(pk.0 .0);
            let rust_msgs: Vec<_> = attrs.into_iter().map(|a| a.0).collect();

            let result = encrypt_batch(&rust_msgs, &key, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            let py_result: Vec<PyEncryptedAttribute> = result.into_iter().map(PyEncryptedAttribute).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyLongPseudonym>
    #[cfg(feature = "long")]
    if let Ok(lps) = messages.extract::<Vec<PyLongPseudonym>>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
            let key = PseudonymSessionPublicKey::from(pk.0 .0);
            let rust_msgs: Vec<_> = lps.into_iter().map(|p| p.0).collect();

            let result = encrypt_batch(&rust_msgs, &key, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            let py_result: Vec<PyLongEncryptedPseudonym> = result.into_iter().map(PyLongEncryptedPseudonym).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyLongAttribute>
    #[cfg(feature = "long")]
    if let Ok(las) = messages.extract::<Vec<PyLongAttribute>>() {
        if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
            let key = AttributeSessionPublicKey::from(pk.0 .0);
            let rust_msgs: Vec<_> = las.into_iter().map(|a| a.0).collect();

            let result = encrypt_batch(&rust_msgs, &key, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            let py_result: Vec<PyLongEncryptedAttribute> = result.into_iter().map(PyLongEncryptedAttribute).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyPEPJSONValue> with PySessionKeys
    #[cfg(feature = "json")]
    if let Ok(jsons) = messages.extract::<Vec<PyPEPJSONValue>>() {
        if let Ok(pk) = public_key.extract::<PyGlobalPublicKeys>() {
            let keys = SessionKeys {
                pseudonym: PseudonymSessionKeys {
                    public: PseudonymGlobalPublicKey(*pk.pseudonym.0),
                    secret: None,
                },
                attribute: AttributeSessionKeys {
                    public: AttributeGlobalPublicKey(*pk.attribute.0),
                    secret: None,
                },
            };
            let rust_msgs: Vec<_> = jsons.into_iter().map(|j| j.0).collect();

            // True Batch: Calculates unified padding for JSON structures
            let result = encrypt_batch(&rust_msgs, &keys, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

            let py_result: Vec<PyEncryptedPEPJSONValue> = result.into_iter().map(PyEncryptedPEPJSONValue).collect();
            return py_result.into_py_any(py);
        }
    }

    Err(PyTypeError::new_err(
        "encrypt_batch() requires (Vec[unencrypted_type], matching_public_key)",
    ))
}
/// Polymorphic batch decryption.
/// Decrypts a list of encrypted messages with a session secret key.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_batch")]
pub fn py_decrypt_batch(
    encrypted: &Bound<PyAny>,
    secret_key: &Bound<PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try Vec<PyEncryptedPseudonym> with PyPseudonymSessionSecretKey
    if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymSessionSecretKey>() {
            let key = PseudonymSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = eps.into_iter().map(|e| e.0).collect();

            // True Batch Decryption
            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyPseudonym> = result.into_iter().map(PyPseudonym).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyEncryptedAttribute> with PyAttributeSessionSecretKey
    if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeSessionSecretKey>() {
            let key = AttributeSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = eas.into_iter().map(|e| e.0).collect();

            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyAttribute> = result.into_iter().map(PyAttribute).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyLongEncryptedPseudonym>
    #[cfg(feature = "long")]
    if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymSessionSecretKey>() {
            let key = PseudonymSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = leps.into_iter().map(|e| e.0).collect();

            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyLongPseudonym> = result.into_iter().map(PyLongPseudonym).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyLongEncryptedAttribute>
    #[cfg(feature = "long")]
    if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeSessionSecretKey>() {
            let key = AttributeSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = leas.into_iter().map(|e| e.0).collect();

            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyLongAttribute> = result.into_iter().map(PyLongAttribute).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyEncryptedPEPJSONValue> with PySessionKeys
    #[cfg(feature = "json")]
    if let Ok(jsons) = encrypted.extract::<Vec<PyEncryptedPEPJSONValue>>() {
        if let Ok(k) = secret_key.extract::<crate::keys::py::PySessionKeys>() {
            let rust_encs: Vec<_> = jsons.into_iter().map(|j| j.0).collect();
            let keys = SessionKeys::from(k);

            // True Batch Decryption: handles unpadding of JSON structures
            let result = decrypt_batch(&rust_encs, &keys)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyPEPJSONValue> = result.into_iter().map(PyPEPJSONValue).collect();
            return py_result.into_py_any(py);
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_batch() requires (Vec[encrypted_type], matching_secret_key)",
    ))
}

/// Polymorphic batch decryption.
/// Decrypts a list of encrypted messages with a session secret key.
pub fn py_decrypt_batch(
    encrypted: &Bound<PyAny>,
    secret_key: &Bound<PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try Vec<PyEncryptedPseudonym> with PyPseudonymSessionSecretKey
    if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymSessionSecretKey>() {
            let key = PseudonymSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = eps.into_iter().map(|e| e.0).collect();

            // True Batch Decryption: handles potential reordering/shuffling
            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyPseudonym> = result.into_iter().map(PyPseudonym).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyEncryptedAttribute> with PyAttributeSessionSecretKey
    if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeSessionSecretKey>() {
            let key = AttributeSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = eas.into_iter().map(|e| e.0).collect();

            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyAttribute> = result.into_iter().map(PyAttribute).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyLongEncryptedPseudonym>
    #[cfg(feature = "long")]
    if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymSessionSecretKey>() {
            let key = PseudonymSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = leps.into_iter().map(|e| e.0).collect();

            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyLongPseudonym> = result.into_iter().map(PyLongPseudonym).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyLongEncryptedAttribute>
    #[cfg(feature = "long")]
    if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeSessionSecretKey>() {
            let key = AttributeSessionSecretKey::from(sk.0 .0);
            let rust_encs: Vec<_> = leas.into_iter().map(|e| e.0).collect();

            let result = decrypt_batch(&rust_encs, &key)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyLongAttribute> = result.into_iter().map(PyLongAttribute).collect();
            return py_result.into_py_any(py);
        }
    }

    // Try Vec<PyEncryptedPEPJSONValue> with PySessionKeys
    #[cfg(feature = "json")]
    if let Ok(jsons) = encrypted.extract::<Vec<PyEncryptedPEPJSONValue>>() {
        if let Ok(pk) = secret_key.extract::<PyGlobalPublicKeys>() {
            let keys = GlobalPublicKeys {
                pseudonym: PseudonymGlobalPublicKey(*pk.pseudonym.0),
                attribute: AttributeGlobalPublicKey(*pk.attribute.0)
            };
            let rust_encs: Vec<_> = jsons.into_iter().map(|j| j.0).collect();

            // True Batch Decryption: handles automatic unpadding of JSON data
            let result = decrypt_batch(&rust_encs, &keys)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e)))?;

            let py_result: Vec<PyPEPJSONValue> = result.into_iter().map(PyPEPJSONValue).collect();
            return py_result.into_py_any(py);
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_batch() requires (Vec[encrypted_type], matching_secret_key)",
    ))
}

/// Polymorphic batch encryption with global public key.
/// Encrypts a list of unencrypted messages with a global public key.
#[cfg(feature = "offline")]
#[pyfunction]
#[pyo3(name = "encrypt_global_batch")]
pub fn py_encrypt_global_batch(
    messages: &Bound<PyAny>,
    public_key: &Bound<PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = messages.py();
    let mut rng = rand::rng();

    // Try Vec<Pseudonym> with PseudonymGlobalPublicKey
    if let Ok(ps) = messages.extract::<Vec<PyPseudonym>>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymGlobalPublicKey>() {
            let key = PseudonymGlobalPublicKey(pk.0 .0);
            let result: Vec<PyEncryptedPseudonym> = ps
                .into_iter()
                .map(|p| PyEncryptedPseudonym(encrypt_global(&p.0, &key, &mut rng)))
                .collect();
            return result.into_py_any(py);
        }
    }

    // Try Vec<Attribute> with AttributeGlobalPublicKey
    if let Ok(attrs) = messages.extract::<Vec<PyAttribute>>() {
        if let Ok(pk) = public_key.extract::<PyAttributeGlobalPublicKey>() {
            let key = AttributeGlobalPublicKey(pk.0 .0);
            let result: Vec<PyEncryptedAttribute> = attrs
                .into_iter()
                .map(|a| PyEncryptedAttribute(encrypt_global(&a.0, &key, &mut rng)))
                .collect();
            return result.into_py_any(py);
        }
    }

    // Try Vec<LongPseudonym> with PseudonymGlobalPublicKey
    #[cfg(feature = "long")]
    if let Ok(lps) = messages.extract::<Vec<PyLongPseudonym>>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymGlobalPublicKey>() {
            let key = PseudonymGlobalPublicKey(pk.0 .0);
            let result: Vec<PyLongEncryptedPseudonym> = lps
                .into_iter()
                .map(|p| PyLongEncryptedPseudonym(encrypt_global(&p.0, &key, &mut rng)))
                .collect();
            return result.into_py_any(py);
        }
    }

    // Try Vec<LongAttribute> with AttributeGlobalPublicKey
    #[cfg(feature = "long")]
    if let Ok(las) = messages.extract::<Vec<PyLongAttribute>>() {
        if let Ok(pk) = public_key.extract::<PyAttributeGlobalPublicKey>() {
            let key = AttributeGlobalPublicKey(pk.0 .0);
            let result: Vec<PyLongEncryptedAttribute> = las
                .into_iter()
                .map(|a| PyLongEncryptedAttribute(encrypt_global(&a.0, &key, &mut rng)))
                .collect();
            return result.into_py_any(py);
        }
    }

    // Try Vec<PEPJSONValue> with GlobalKeys
    #[cfg(feature = "json")]
    if let Ok(jsons) = messages.extract::<Vec<PyPEPJSONValue>>() {
        if let Ok(keys) = public_key.extract::<PyTranscryptionInfo>() {
            let info = TranscryptionInfo::from(keys);
            let result: Vec<PyEncryptedPEPJSONValue> = jsons
                .into_iter()
                .map(|j| PyEncryptedPEPJSONValue(j.0.encrypt_global(&info, &mut rng)))
                .collect();
            return result.into_py_any(py);
        }
    }

    Err(PyTypeError::new_err(
        "encrypt_global_batch() requires (Vec[unencrypted_type], matching_global_public_key)",
    ))
}

/// Polymorphic batch decryption with global secret key.
/// Decrypts a list of encrypted messages with a global secret key.
#[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_global_batch")]
pub fn py_decrypt_global_batch(
    encrypted: &Bound<PyAny>,
    secret_key: &Bound<PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try Vec<EncryptedPseudonym> with PseudonymGlobalSecretKey
    if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            let result: Vec<_> = eps
                .into_iter()
                .map(|ep| {
                    decrypt_global(&ep.0, &key)
                        .map(PyPseudonym)
                        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            return result.into_py_any(py);
        }
    }

    // Try Vec<EncryptedAttribute> with AttributeGlobalSecretKey
    if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            let result: Vec<_> = eas
                .into_iter()
                .map(|ea| {
                    decrypt_global(&ea.0, &key)
                        .map(PyAttribute)
                        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            return result.into_py_any(py);
        }
    }

    // Try Vec<LongEncryptedPseudonym> with PseudonymGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            let result: Vec<_> = leps
                .into_iter()
                .map(|lep| {
                    decrypt_global(&lep.0, &key)
                        .map(PyLongPseudonym)
                        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            return result.into_py_any(py);
        }
    }

    // Try Vec<LongEncryptedAttribute> with AttributeGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            let result: Vec<_> = leas
                .into_iter()
                .map(|lea| {
                    decrypt_global(&lea.0, &key)
                        .map(PyLongAttribute)
                        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            return result.into_py_any(py);
        }
    }

    // Try Vec<EncryptedPEPJSONValue> with GlobalKeys
    #[cfg(feature = "json")]
    if let Ok(jsons) = encrypted.extract::<Vec<PyEncryptedPEPJSONValue>>() {
        if let Ok(keys) = secret_key.extract::<PyTranscryptionInfo>() {
            let info = TranscryptionInfo::from(keys);
            let result: Vec<_> = jsons
                .into_iter()
                .map(|j| {
                    j.0.decrypt_global(&info)
                        .map(PyPEPJSONValue)
                        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            return result.into_py_any(py);
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_global_batch() requires (Vec[encrypted_type], matching_global_secret_key)",
    ))
}

/// Polymorphic batch decryption with global secret key.
/// Decrypts a list of encrypted messages with a global secret key.
#[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "decrypt_global_batch")]
pub fn py_decrypt_global_batch(
    encrypted: &Bound<PyAny>,
    secret_key: &Bound<PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try Vec<EncryptedPseudonym> with PseudonymGlobalSecretKey
    if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            let result: Vec<PyPseudonym> = eps
                .into_iter()
                .map(|ep| PyPseudonym(decrypt_global(&ep.0, &key)))
                .collect();
            return Ok(result.into_py_any(py)?);
        }
    }

    // Try Vec<EncryptedAttribute> with AttributeGlobalSecretKey
    if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            let result: Vec<PyAttribute> = eas
                .into_iter()
                .map(|ea| PyAttribute(decrypt_global(&ea.0, &key)))
                .collect();
            return Ok(result.into_py_any(py)?);
        }
    }

    // Try Vec<LongEncryptedPseudonym> with PseudonymGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            let result: Vec<PyLongPseudonym> = leps
                .into_iter()
                .map(|lep| PyLongPseudonym(decrypt_global(&lep.0, &key)))
                .collect();
            return Ok(result.into_py_any(py)?);
        }
    }

    // Try Vec<LongEncryptedAttribute> with AttributeGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            let result: Vec<PyLongAttribute> = leas
                .into_iter()
                .map(|lea| PyLongAttribute(decrypt_global(&lea.0, &key)))
                .collect();
            return Ok(result.into_py_any(py)?);
        }
    }

    // Try Vec<EncryptedPEPJSONValue> with GlobalKeys
    #[cfg(feature = "json")]
    if let Ok(jsons) = encrypted.extract::<Vec<PyEncryptedPEPJSONValue>>() {
        if let Ok(keys) = secret_key.extract::<PyTranscryptionInfo>() {
            let info = TranscryptionInfo::from(keys);
            let result: Vec<PyPEPJSONValue> = jsons
                .into_iter()
                .map(|j| PyPEPJSONValue(j.0.decrypt_global(&info)))
                .collect();
            return Ok(result.into_py_any(py)?);
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_global_batch() requires (Vec[encrypted_type], matching_global_secret_key)",
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_pseudonymize_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_batch, m)?)?;

    #[cfg(feature = "offline")]
    {
        m.add_function(wrap_pyfunction!(py_encrypt_global_batch, m)?)?;
        #[cfg(feature = "insecure")]
        m.add_function(wrap_pyfunction!(py_decrypt_global_batch, m)?)?;
    }

    Ok(())
}
