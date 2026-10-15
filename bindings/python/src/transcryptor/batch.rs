//! Python bindings for batch transcryption operations.

#[cfg(feature = "json")]
use crate::data::json::PyEncryptedPepJsonValue;
#[cfg(feature = "long")]
use crate::data::long::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::data::records::PyEncryptedRecord;
use crate::data::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::types::{
    PyAttributeRekeyInfo, PyPseudonymRekeyInfo, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use libpep::factors::{AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo};
use libpep::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

/// Extract every item of a list as one type: `None` when the first item is not of that type
/// (so that another type can be tried), a `TypeError` when a later item is not.
macro_rules! extract_all {
    ($items:expr, $t:ty) => {{
        let items: &[Bound<PyAny>] = &$items;
        match items.first() {
            Some(first) if first.extract::<$t>().is_err() => None,
            _ => Some(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| {
                        item.extract::<$t>().map_err(|_| {
                            PyTypeError::new_err(format!(
                                "item {i} is not of the same type as item 0"
                            ))
                        })
                    })
                    .collect::<PyResult<Vec<$t>>>()?,
            ),
        }
    }};
}

/// Polymorphic batch pseudonymization.
/// Accepts a mutable list of encrypted pseudonyms and pseudonymization info.
#[pyfunction]
#[pyo3(name = "pseudonymize_batch", signature = (encrypted, info, public_key=None))]
#[allow(clippy::expect_used)]
pub fn py_pseudonymize_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyPseudonymizationInfo,
    public_key: Option<&Bound<PyAny>>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();
    let pseudonymization_info = PseudonymizationInfo::from(info);

    // Try EncryptedPseudonym
    if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
        let encs: Vec<_> = encrypted
            .iter()
            .map(|e| e.extract::<PyEncryptedPseudonym>())
            .collect::<Result<Vec<_>, _>>()?;
        let rust_encs: Vec<_> = encs.iter().map(|e| e.0).collect();
        let result = crate::transcrypt_with!(pseudonymize_batch, &rust_encs, &pseudonymization_info, public_key => crate::keys::pk::pseudonym, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    // Try LongEncryptedPseudonym
    #[cfg(feature = "long")]
    if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
        let encs: Vec<_> = encrypted
            .iter()
            .map(|e| e.extract::<PyLongEncryptedPseudonym>())
            .collect::<Result<Vec<_>, _>>()?;
        let rust_encs: Vec<_> = encs.iter().map(|e| e.0.clone()).collect();
        let result = crate::transcrypt_with!(pseudonymize_batch, &rust_encs, &pseudonymization_info, public_key => crate::keys::pk::pseudonym, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_iter()
            .map(|e| {
                Py::new(py, PyLongEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    Err(PyTypeError::new_err(
        "pseudonymize_batch() requires list of EncryptedPseudonym or LongEncryptedPseudonym",
    ))
}

/// Polymorphic batch rekeying.
/// Accepts a mutable list of encrypted values and rekey info.
#[pyfunction]
#[pyo3(name = "rekey_batch", signature = (encrypted, rekey_info, public_key=None))]
#[allow(clippy::expect_used)]
pub fn py_rekey_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    rekey_info: &Bound<PyAny>,
    public_key: Option<&Bound<PyAny>>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();

    // Try EncryptedPseudonym with PseudonymRekeyInfo
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyInfo>() {
        if let Some(encs) = extract_all!(encrypted, PyEncryptedPseudonym) {
            let rust_encs: Vec<_> = encs.into_iter().map(|e| e.0).collect();
            let result = crate::transcrypt_with!(rekey_batch, &rust_encs, &info.0, public_key => crate::keys::pk::pseudonym, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongEncryptedPseudonym with PseudonymRekeyInfo
    #[cfg(feature = "long")]
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyInfo>() {
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
            let result = crate::transcrypt_with!(rekey_batch, &rust_encs, &info.0, public_key => crate::keys::pk::pseudonym, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
                .into_iter()
                .map(|e| {
                    Py::new(py, PyLongEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try EncryptedAttribute with AttributeRekeyInfo
    if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
        if let Some(encs) = extract_all!(encrypted, PyEncryptedAttribute) {
            let rust_encs: Vec<_> = encs.into_iter().map(|e| e.0).collect();
            let rust_info = AttributeRekeyInfo::from(&info);
            let result = crate::transcrypt_with!(rekey_batch, &rust_encs, &rust_info, public_key => crate::keys::pk::attribute, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedAttribute(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongEncryptedAttribute with AttributeRekeyInfo
    #[cfg(feature = "long")]
    if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
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
            let rust_info = AttributeRekeyInfo::from(&info);
            let result = crate::transcrypt_with!(rekey_batch, &rust_encs, &rust_info, public_key => crate::keys::pk::attribute, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
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
        "rekey_batch() requires list of encrypted values and matching rekey info",
    ))
}

/// Polymorphic batch transcryption.
/// Accepts a mutable list of encrypted values and transcryption info.
#[pyfunction]
#[pyo3(name = "transcrypt_batch", signature = (encrypted, info, public_key=None))]
#[allow(clippy::expect_used)]
pub fn py_transcrypt_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyTranscryptionInfo,
    public_key: Option<&Bound<PyAny>>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();
    let transcryption_info = TranscryptionInfo::from(info);

    // Try EncryptedPseudonym
    if let Some(encs) = extract_all!(encrypted, PyEncryptedPseudonym) {
        let rust_encs: Vec<_> = encs.into_iter().map(|e| e.0).collect();
        let result = crate::transcrypt_with!(transcrypt_batch, &rust_encs, &transcryption_info, public_key => crate::keys::pk::pseudonym, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    // Try EncryptedAttribute
    if let Some(encs) = extract_all!(encrypted, PyEncryptedAttribute) {
        let rust_encs: Vec<_> = encs.into_iter().map(|e| e.0).collect();
        let result = crate::transcrypt_with!(transcrypt_batch, &rust_encs, &transcryption_info, public_key => crate::keys::pk::attribute, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedAttribute(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    // Try EncryptedRecord
    if encrypted[0].extract::<PyEncryptedRecord>().is_ok() {
        let rust_encs: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedRecord>()
                    .expect("type already validated")
                    .0
                    .clone()
            })
            .collect();
        let result = crate::transcrypt_with!(transcrypt_batch, &rust_encs, &transcryption_info, public_key => crate::keys::pk::session, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedRecord(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    // Try EncryptedPepJsonValue
    #[cfg(feature = "json")]
    if encrypted[0].extract::<PyEncryptedPepJsonValue>().is_ok() {
        let rust_encs: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedPepJsonValue>()
                    .expect("type already validated")
                    .0
                    .clone()
            })
            .collect();
        let result = crate::transcrypt_with!(transcrypt_batch, &rust_encs, &transcryption_info, public_key => crate::keys::pk::session, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPepJsonValue(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    Err(PyTypeError::new_err(
        "transcrypt_batch() requires list of transcryptable encrypted types",
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_pseudonymize_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_batch, m)?)?;
    Ok(())
}
