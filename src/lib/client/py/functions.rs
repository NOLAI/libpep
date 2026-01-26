#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::client::decrypt_global;
#[cfg(feature = "offline")]
use crate::client::encrypt_global;
use crate::client::{decrypt, encrypt};
#[cfg(feature = "batch")]
use crate::client::{decrypt_batch, encrypt_batch};
#[cfg(feature = "json")]
use crate::data::py::json::{PyEncryptedPEPJSONValue, PyPEPJSONValue};
#[cfg(feature = "long")]
use crate::data::py::long::{
    PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym, PyLongPseudonym,
};
use crate::data::py::records::{PyEncryptedRecord, PyRecord};
#[cfg(feature = "long")]
use crate::data::py::records::{PyLongEncryptedRecord, PyLongRecord};
use crate::data::py::simple::{
    PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym,
};
#[cfg(feature = "offline")]
use crate::keys::py::types::{PyAttributeGlobalPublicKey, PyPseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::py::types::{PyAttributeGlobalSecretKey, PyPseudonymGlobalSecretKey};
use crate::keys::py::PySessionKeys;
use crate::keys::py::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey,
};
#[cfg(feature = "offline")]
use crate::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey, SessionKeys,
};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

// ============================================================================
// Polymorphic Encryption/Decryption Functions
// ============================================================================

/// Polymorphic encrypt function - works with any encryptable type.
///
/// Supports:
/// - Pseudonym + PseudonymSessionPublicKey
/// - Attribute + AttributeSessionPublicKey
/// - LongPseudonym + PseudonymSessionPublicKey
/// - LongAttribute + AttributeSessionPublicKey
/// - Record + SessionKeys
/// - LongRecord + SessionKeys
/// - PEPJSONValue + SessionKeys
#[pyfunction]
#[pyo3(name = "encrypt")]
pub fn py_encrypt(data: &Bound<PyAny>, key: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = data.py();

    // Try Pseudonym + PseudonymSessionPublicKey
    if let (Ok(p), Ok(k)) = (
        data.extract::<PyPseudonym>(),
        key.extract::<PyPseudonymSessionPublicKey>(),
    ) {
        let mut rng = rand::rng();
        let encrypted = encrypt(&p.0, &PseudonymSessionPublicKey::from(k.0 .0), &mut rng);
        return Ok(Py::new(py, PyEncryptedPseudonym(encrypted))?.into_any());
    }

    // Try Attribute + AttributeSessionPublicKey
    if let (Ok(a), Ok(k)) = (
        data.extract::<PyAttribute>(),
        key.extract::<PyAttributeSessionPublicKey>(),
    ) {
        let mut rng = rand::rng();
        let encrypted = encrypt(&a.0, &AttributeSessionPublicKey::from(k.0 .0), &mut rng);
        return Ok(Py::new(py, PyEncryptedAttribute(encrypted))?.into_any());
    }

    // Try LongPseudonym + PseudonymSessionPublicKey
    #[cfg(feature = "long")]
    if let (Ok(lp), Ok(k)) = (
        data.extract::<PyLongPseudonym>(),
        key.extract::<PyPseudonymSessionPublicKey>(),
    ) {
        let mut rng = rand::rng();
        let encrypted = encrypt(&lp.0, &PseudonymSessionPublicKey::from(k.0 .0), &mut rng);
        return Ok(Py::new(py, PyLongEncryptedPseudonym(encrypted))?.into_any());
    }

    // Try LongAttribute + AttributeSessionPublicKey
    #[cfg(feature = "long")]
    if let (Ok(la), Ok(k)) = (
        data.extract::<PyLongAttribute>(),
        key.extract::<PyAttributeSessionPublicKey>(),
    ) {
        let mut rng = rand::rng();
        let encrypted = encrypt(&la.0, &AttributeSessionPublicKey::from(k.0 .0), &mut rng);
        return Ok(Py::new(py, PyLongEncryptedAttribute(encrypted))?.into_any());
    }

    // Try Record + SessionKeys
    if let (Ok(rec), Ok(k)) = (data.extract::<PyRecord>(), key.extract::<PySessionKeys>()) {
        let mut rng = rand::rng();
        let keys: SessionKeys = k.clone().into();
        let encrypted = encrypt(&rec.0, &keys, &mut rng);
        return Ok(Py::new(py, PyEncryptedRecord(encrypted))?.into_any());
    }

    // Try LongRecord + SessionKeys
    #[cfg(feature = "long")]
    if let (Ok(lrec), Ok(k)) = (
        data.extract::<PyLongRecord>(),
        key.extract::<PySessionKeys>(),
    ) {
        let mut rng = rand::rng();
        let keys: SessionKeys = k.clone().into();
        let encrypted = encrypt(&lrec.0, &keys, &mut rng);
        return Ok(Py::new(py, PyLongEncryptedRecord(encrypted))?.into_any());
    }

    // Try PEPJSONValue + SessionKeys
    #[cfg(feature = "json")]
    if let (Ok(json), Ok(k)) = (
        data.extract::<PyPEPJSONValue>(),
        key.extract::<PySessionKeys>(),
    ) {
        let mut rng = rand::rng();
        let keys: SessionKeys = k.clone().into();
        let encrypted = encrypt(&json.0, &keys, &mut rng);
        return Ok(Py::new(py, PyEncryptedPEPJSONValue(encrypted))?.into_any());
    }

    Err(PyTypeError::new_err(
        "encrypt() requires (Pseudonym|Attribute|LongPseudonym|LongAttribute|Record|LongRecord|PEPJSONValue) and matching key type"
    ))
}

/// Polymorphic decrypt function - works with any encrypted type.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt")]
#[allow(clippy::expect_used)]
pub fn py_decrypt(encrypted: &Bound<PyAny>, key: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try EncryptedPseudonym + PseudonymSessionSecretKey
    if let (Ok(ep), Ok(k)) = (
        encrypted.extract::<PyEncryptedPseudonym>(),
        key.extract::<PyPseudonymSessionSecretKey>(),
    ) {
        return decrypt(&ep.0, &PseudonymSessionSecretKey::from(k.0 .0))
            .map(|p| {
                Py::new(py, PyPseudonym(p))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .ok_or_else(|| PyTypeError::new_err("Decryption failed"));
    }

    // Try EncryptedAttribute + AttributeSessionSecretKey
    if let (Ok(ea), Ok(k)) = (
        encrypted.extract::<PyEncryptedAttribute>(),
        key.extract::<PyAttributeSessionSecretKey>(),
    ) {
        return decrypt(&ea.0, &AttributeSessionSecretKey::from(k.0 .0))
            .map(|a| {
                Py::new(py, PyAttribute(a))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .ok_or_else(|| PyTypeError::new_err("Decryption failed"));
    }

    // Try LongEncryptedPseudonym + PseudonymSessionSecretKey
    #[cfg(feature = "long")]
    if let (Ok(lep), Ok(k)) = (
        encrypted.extract::<PyLongEncryptedPseudonym>(),
        key.extract::<PyPseudonymSessionSecretKey>(),
    ) {
        return decrypt(&lep.0, &PseudonymSessionSecretKey::from(k.0 .0))
            .map(|p| Py::new(py, PyLongPseudonym(p)).map(|p| p.into_any()))
            .ok_or_else(|| PyTypeError::new_err("Decryption failed"))?;
    }

    // Try LongEncryptedAttribute + AttributeSessionSecretKey
    #[cfg(feature = "long")]
    if let (Ok(lea), Ok(k)) = (
        encrypted.extract::<PyLongEncryptedAttribute>(),
        key.extract::<PyAttributeSessionSecretKey>(),
    ) {
        return decrypt(&lea.0, &AttributeSessionSecretKey::from(k.0 .0))
            .map(|a| Py::new(py, PyLongAttribute(a)).map(|a| a.into_any()))
            .ok_or_else(|| PyTypeError::new_err("Decryption failed"))?;
    }

    // Try EncryptedRecord + SessionKeys
    if let (Ok(er), Ok(k)) = (
        encrypted.extract::<PyEncryptedRecord>(),
        key.extract::<PySessionKeys>(),
    ) {
        let keys: SessionKeys = k.clone().into();
        return decrypt(&er.0, &keys)
            .map(|r| Py::new(py, PyRecord(r)).map(|p| p.into_any()))
            .ok_or_else(|| PyTypeError::new_err("Decryption failed"))?;
    }

    // Try LongEncryptedRecord + SessionKeys
    #[cfg(feature = "long")]
    if let (Ok(ler), Ok(k)) = (
        encrypted.extract::<PyLongEncryptedRecord>(),
        key.extract::<PySessionKeys>(),
    ) {
        let keys: SessionKeys = k.clone().into();
        return decrypt(&ler.0, &keys)
            .map(|r| Py::new(py, PyLongRecord(r)).map(|p| p.into_any()))
            .ok_or_else(|| PyTypeError::new_err("Decryption failed"))?;
    }

    // Try EncryptedPEPJSONValue + SessionKeys
    #[cfg(feature = "json")]
    if let (Ok(ej), Ok(k)) = (
        encrypted.extract::<PyEncryptedPEPJSONValue>(),
        key.extract::<PySessionKeys>(),
    ) {
        let keys: SessionKeys = k.clone().into();
        return decrypt(&ej.0, &keys)
            .map(|j| Py::new(py, PyPEPJSONValue(j)).map(|p| p.into_any()))
            .ok_or_else(|| PyTypeError::new_err("Decryption failed"))?;
    }

    Err(PyTypeError::new_err(
        "decrypt() requires encrypted type and matching key type",
    ))
}

/// Polymorphic decrypt function - works with any encrypted type.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt")]
pub fn py_decrypt(encrypted: &Bound<PyAny>, key: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try EncryptedPseudonym + PseudonymSessionSecretKey
    if let (Ok(ep), Ok(k)) = (
        encrypted.extract::<PyEncryptedPseudonym>(),
        key.extract::<PyPseudonymSessionSecretKey>(),
    ) {
        let decrypted = decrypt(&ep.0, &PseudonymSessionSecretKey::from(k.0 .0));
        return Ok(Py::new(py, PyPseudonym(decrypted))?.into_any());
    }

    // Try EncryptedAttribute + AttributeSessionSecretKey
    if let (Ok(ea), Ok(k)) = (
        encrypted.extract::<PyEncryptedAttribute>(),
        key.extract::<PyAttributeSessionSecretKey>(),
    ) {
        let decrypted = decrypt(&ea.0, &AttributeSessionSecretKey::from(k.0 .0));
        return Ok(Py::new(py, PyAttribute(decrypted))?.into_any());
    }

    // Try LongEncryptedPseudonym + PseudonymSessionSecretKey
    #[cfg(feature = "long")]
    if let (Ok(lep), Ok(k)) = (
        encrypted.extract::<PyLongEncryptedPseudonym>(),
        key.extract::<PyPseudonymSessionSecretKey>(),
    ) {
        let decrypted = decrypt(&lep.0, &PseudonymSessionSecretKey::from(k.0 .0));
        return Ok(Py::new(py, PyLongPseudonym(decrypted))?.into_any());
    }

    // Try LongEncryptedAttribute + AttributeSessionSecretKey
    #[cfg(feature = "long")]
    if let (Ok(lea), Ok(k)) = (
        encrypted.extract::<PyLongEncryptedAttribute>(),
        key.extract::<PyAttributeSessionSecretKey>(),
    ) {
        let decrypted = decrypt(&lea.0, &AttributeSessionSecretKey::from(k.0 .0));
        return Ok(Py::new(py, PyLongAttribute(decrypted))?.into_any());
    }

    // Try EncryptedRecord + SessionKeys
    if let (Ok(er), Ok(k)) = (
        encrypted.extract::<PyEncryptedRecord>(),
        key.extract::<PySessionKeys>(),
    ) {
        let keys: SessionKeys = k.clone().into();
        let decrypted = decrypt(&er.0, &keys);
        return Ok(Py::new(py, PyRecord(decrypted))?.into_any());
    }

    // Try LongEncryptedRecord + SessionKeys
    #[cfg(feature = "long")]
    if let (Ok(ler), Ok(k)) = (
        encrypted.extract::<PyLongEncryptedRecord>(),
        key.extract::<PySessionKeys>(),
    ) {
        let keys: SessionKeys = k.clone().into();
        let decrypted = decrypt(&ler.0, &keys);
        return Ok(Py::new(py, PyLongRecord(decrypted))?.into_any());
    }

    // Try EncryptedPEPJSONValue + SessionKeys
    #[cfg(feature = "json")]
    if let (Ok(ej), Ok(k)) = (
        encrypted.extract::<PyEncryptedPEPJSONValue>(),
        key.extract::<PySessionKeys>(),
    ) {
        let keys: SessionKeys = k.clone().into();
        let decrypted = decrypt(&ej.0, &keys);
        return Ok(Py::new(py, PyPEPJSONValue(decrypted))?.into_any());
    }

    Err(PyTypeError::new_err(
        "decrypt() requires encrypted type and matching key type",
    ))
}

// ============================================================================
// Offline Encryption Functions
// ============================================================================

/// Polymorphic encrypt_global function for offline encryption.
/// Works with any encryptable type using global public keys.
#[cfg(feature = "offline")]
#[pyfunction]
#[pyo3(name = "encrypt_global")]
pub fn py_encrypt_global(message: &Bound<PyAny>, public_key: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = message.py();
    let mut rng = rand::rng();

    // Try Pseudonym with PseudonymGlobalPublicKey
    if let Ok(p) = message.extract::<PyPseudonym>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymGlobalPublicKey>() {
            let key = PseudonymGlobalPublicKey(pk.0 .0);
            let result = encrypt_global(&p.0, &key, &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try Attribute with AttributeGlobalPublicKey
    if let Ok(a) = message.extract::<PyAttribute>() {
        if let Ok(pk) = public_key.extract::<PyAttributeGlobalPublicKey>() {
            let key = AttributeGlobalPublicKey(pk.0 .0);
            let result = encrypt_global(&a.0, &key, &mut rng);
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }
    }

    // Try LongPseudonym with PseudonymGlobalPublicKey
    #[cfg(feature = "long")]
    if let Ok(lp) = message.extract::<PyLongPseudonym>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymGlobalPublicKey>() {
            let key = PseudonymGlobalPublicKey(pk.0 .0);
            let result = encrypt_global(&lp.0, &key, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try LongAttribute with AttributeGlobalPublicKey
    #[cfg(feature = "long")]
    if let Ok(la) = message.extract::<PyLongAttribute>() {
        if let Ok(pk) = public_key.extract::<PyAttributeGlobalPublicKey>() {
            let key = AttributeGlobalPublicKey(pk.0 .0);
            let result = encrypt_global(&la.0, &key, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }
    }

    Err(PyTypeError::new_err(
        "encrypt_global() requires (unencrypted_type, matching_global_public_key)",
    ))
}

/// Polymorphic decrypt_global function for offline decryption.
/// Works with any encrypted type using global secret keys.
/// Returns None if decryption fails (elgamal3 feature).
#[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_global")]
pub fn py_decrypt_global(
    encrypted: &Bound<PyAny>,
    secret_key: &Bound<PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try EncryptedPseudonym with PseudonymGlobalSecretKey
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            if let Some(result) = decrypt_global(&ep.0, &key) {
                return Ok(Py::new(py, PyPseudonym(result))?.into_any());
            }
            return Err(pyo3::exceptions::PyValueError::new_err("Decryption failed"));
        }
    }

    // Try EncryptedAttribute with AttributeGlobalSecretKey
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            if let Some(result) = decrypt_global(&ea.0, &key) {
                return Ok(Py::new(py, PyAttribute(result))?.into_any());
            }
            return Err(pyo3::exceptions::PyValueError::new_err("Decryption failed"));
        }
    }

    // Try LongEncryptedPseudonym with PseudonymGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            if let Some(result) = decrypt_global(&lep.0, &key) {
                return Ok(Py::new(py, PyLongPseudonym(result))?.into_any());
            }
            return Err(pyo3::exceptions::PyValueError::new_err("Decryption failed"));
        }
    }

    // Try LongEncryptedAttribute with AttributeGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            if let Some(result) = decrypt_global(&lea.0, &key) {
                return Ok(Py::new(py, PyLongAttribute(result))?.into_any());
            }
            return Err(pyo3::exceptions::PyValueError::new_err("Decryption failed"));
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_global() requires (encrypted_type, matching_global_secret_key)",
    ))
}

/// Polymorphic decrypt_global function for offline decryption.
/// Works with any encrypted type using global secret keys.
#[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "decrypt_global")]
pub fn py_decrypt_global(
    encrypted: &Bound<PyAny>,
    secret_key: &Bound<PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try EncryptedPseudonym with PseudonymGlobalSecretKey
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            let result = decrypt_global(&ep.0, &key);
            return Ok(Py::new(py, PyPseudonym(result))?.into_any());
        }
    }

    // Try EncryptedAttribute with AttributeGlobalSecretKey
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            let result = decrypt_global(&ea.0, &key);
            return Ok(Py::new(py, PyAttribute(result))?.into_any());
        }
    }

    // Try LongEncryptedPseudonym with PseudonymGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        if let Ok(sk) = secret_key.extract::<PyPseudonymGlobalSecretKey>() {
            let key = PseudonymGlobalSecretKey(sk.0 .0);
            let result = decrypt_global(&lep.0, &key);
            return Ok(Py::new(py, PyLongPseudonym(result))?.into_any());
        }
    }

    // Try LongEncryptedAttribute with AttributeGlobalSecretKey
    #[cfg(feature = "long")]
    if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
        if let Ok(sk) = secret_key.extract::<PyAttributeGlobalSecretKey>() {
            let key = AttributeGlobalSecretKey(sk.0 .0);
            let result = decrypt_global(&lea.0, &key);
            return Ok(Py::new(py, PyLongAttribute(result))?.into_any());
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_global() requires (encrypted_type, matching_global_secret_key)",
    ))
}

// ============================================================================
// Batch Functions
// ============================================================================

/// Polymorphic batch encryption with session public keys.
/// Accepts a list of encryptable values and a public key, returns a list of encrypted values.
#[cfg(feature = "batch")]
#[pyfunction]
#[pyo3(name = "encrypt_batch")]
#[allow(clippy::expect_used)]
pub fn py_encrypt_batch(
    py: Python,
    messages: Vec<Bound<PyAny>>,
    key: &Bound<PyAny>,
) -> PyResult<Vec<Py<PyAny>>> {
    if messages.is_empty() {
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();

    // Try Pseudonym + PseudonymSessionPublicKey
    if let Ok(pk) = key.extract::<PyPseudonymSessionPublicKey>() {
        if messages[0].extract::<PyPseudonym>().is_ok() {
            // Unwrap is safe: type already validated with is_ok() check above
            #[allow(clippy::unwrap_used)]
            let rust_msgs: Vec<_> = messages
                .iter()
                .map(|m| {
                    m.extract::<PyPseudonym>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let encrypted = encrypt_batch(
                &rust_msgs,
                &PseudonymSessionPublicKey::from(pk.0 .0),
                &mut rng,
            )
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(encrypted
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try Attribute + AttributeSessionPublicKey
    if let Ok(pk) = key.extract::<PyAttributeSessionPublicKey>() {
        if messages[0].extract::<PyAttribute>().is_ok() {
            let rust_msgs: Vec<_> = messages
                .iter()
                .map(|m| {
                    m.extract::<PyAttribute>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let encrypted = encrypt_batch(
                &rust_msgs,
                &AttributeSessionPublicKey::from(pk.0 .0),
                &mut rng,
            )
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(encrypted
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedAttribute(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongPseudonym + PseudonymSessionPublicKey
    #[cfg(feature = "long")]
    if let Ok(pk) = key.extract::<PyPseudonymSessionPublicKey>() {
        if messages[0].extract::<PyLongPseudonym>().is_ok() {
            let rust_msgs: Vec<_> = messages
                .iter()
                .map(|m| {
                    m.extract::<PyLongPseudonym>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let encrypted = encrypt_batch(
                &rust_msgs,
                &PseudonymSessionPublicKey::from(pk.0 .0),
                &mut rng,
            )
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(encrypted
                .into_iter()
                .map(|e| {
                    Py::new(py, PyLongEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongAttribute + AttributeSessionPublicKey
    #[cfg(feature = "long")]
    if let Ok(pk) = key.extract::<PyAttributeSessionPublicKey>() {
        if messages[0].extract::<PyLongAttribute>().is_ok() {
            let rust_msgs: Vec<_> = messages
                .iter()
                .map(|m| {
                    m.extract::<PyLongAttribute>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let encrypted = encrypt_batch(
                &rust_msgs,
                &AttributeSessionPublicKey::from(pk.0 .0),
                &mut rng,
            )
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(encrypted
                .into_iter()
                .map(|e| {
                    Py::new(py, PyLongEncryptedAttribute(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    Err(PyTypeError::new_err(
        "encrypt_batch() requires list of (Pseudonym|Attribute|LongPseudonym|LongAttribute) and matching key",
    ))
}

/// Polymorphic batch decryption with session secret keys.
/// Accepts a list of encrypted values and a secret key, returns a list of decrypted values.
#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_batch")]
#[allow(clippy::expect_used)]
pub fn py_decrypt_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    key: &Bound<PyAny>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    // Try EncryptedPseudonym + PseudonymSessionSecretKey
    if let Ok(sk) = key.extract::<PyPseudonymSessionSecretKey>() {
        if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &PseudonymSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyPseudonym(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try EncryptedAttribute + AttributeSessionSecretKey
    if let Ok(sk) = key.extract::<PyAttributeSessionSecretKey>() {
        if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &AttributeSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyAttribute(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongEncryptedPseudonym + PseudonymSessionSecretKey
    #[cfg(feature = "long")]
    if let Ok(sk) = key.extract::<PyPseudonymSessionSecretKey>() {
        if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &PseudonymSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyLongPseudonym(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongEncryptedAttribute + AttributeSessionSecretKey
    #[cfg(feature = "long")]
    if let Ok(sk) = key.extract::<PyAttributeSessionSecretKey>() {
        if encrypted[0].extract::<PyLongEncryptedAttribute>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &AttributeSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyLongAttribute(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_batch() requires list of encrypted types and matching key",
    ))
}

/// Polymorphic batch decryption with session secret keys (non-elgamal3 version).
#[cfg(all(feature = "batch", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "decrypt_batch")]
#[allow(clippy::expect_used)]
pub fn py_decrypt_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    key: &Bound<PyAny>,
) -> PyResult<Vec<Py<PyAny>>> {
    // Same implementation as elgamal3 version, but without error handling for None
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    // Try EncryptedPseudonym + PseudonymSessionSecretKey
    if let Ok(sk) = key.extract::<PyPseudonymSessionSecretKey>() {
        if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &PseudonymSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyPseudonym(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try EncryptedAttribute + AttributeSessionSecretKey
    if let Ok(sk) = key.extract::<PyAttributeSessionSecretKey>() {
        if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &AttributeSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyAttribute(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongEncryptedPseudonym + PseudonymSessionSecretKey
    #[cfg(feature = "long")]
    if let Ok(sk) = key.extract::<PyPseudonymSessionSecretKey>() {
        if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &PseudonymSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyLongPseudonym(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongEncryptedAttribute + AttributeSessionSecretKey
    #[cfg(feature = "long")]
    if let Ok(sk) = key.extract::<PyAttributeSessionSecretKey>() {
        if encrypted[0].extract::<PyLongEncryptedAttribute>().is_ok() {
            let rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let decrypted = decrypt_batch(&rust_encs, &AttributeSessionSecretKey::from(sk.0 .0))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(decrypted
                .into_iter()
                .map(|d| {
                    Py::new(py, PyLongAttribute(d))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    Err(PyTypeError::new_err(
        "decrypt_batch() requires list of encrypted types and matching key",
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register polymorphic functions
    m.add_function(wrap_pyfunction!(py_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt, m)?)?;

    // Register global encryption functions (offline feature only)
    #[cfg(feature = "offline")]
    {
        m.add_function(wrap_pyfunction!(py_encrypt_global, m)?)?;
        #[cfg(feature = "insecure")]
        m.add_function(wrap_pyfunction!(py_decrypt_global, m)?)?;
    }

    // Register batch functions
    #[cfg(feature = "batch")]
    {
        m.add_function(wrap_pyfunction!(py_encrypt_batch, m)?)?;
        m.add_function(wrap_pyfunction!(py_decrypt_batch, m)?)?;
    }

    Ok(())
}
