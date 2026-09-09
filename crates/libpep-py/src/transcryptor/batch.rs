//! Python bindings for batch transcryption operations.

#[cfg(feature = "json")]
use crate::data::py::json::PyEncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::py::long::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::data::py::records::PyEncryptedRecord;
use crate::data::py::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::py::contexts::{
    PyAttributeRekeyInfo, PyPseudonymRekeyFactor, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use crate::factors::{AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo};
use crate::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

/// Polymorphic batch pseudonymization.
/// Accepts a mutable list of encrypted pseudonyms and pseudonymization info.
#[pyfunction]
#[pyo3(name = "pseudonymize_batch")]
#[allow(clippy::expect_used)]
pub fn py_pseudonymize_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyPseudonymizationInfo,
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
        let mut rust_encs: Vec<_> = encs.iter().map(|e| e.0).collect();
        let result = pseudonymize_batch(&mut rust_encs, &pseudonymization_info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_vec()
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
        let mut rust_encs: Vec<_> = encs.iter().map(|e| e.0.clone()).collect();
        let result = pseudonymize_batch(&mut rust_encs, &pseudonymization_info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_vec()
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
#[pyo3(name = "rekey_batch")]
#[allow(clippy::expect_used)]
pub fn py_rekey_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    rekey_info: &Bound<PyAny>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();

    // Try EncryptedPseudonym with PseudonymRekeyFactor
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
        if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
            let mut rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let result = rekey_batch(&mut rust_encs, &info.0, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
                .into_vec()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    // Try LongEncryptedPseudonym with PseudonymRekeyFactor
    #[cfg(feature = "long")]
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
        if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
            let mut rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let result = rekey_batch(&mut rust_encs, &info.0, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
                .into_vec()
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
        if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
            let mut rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let rust_info = AttributeRekeyInfo::from(&info);
            let result = rekey_batch(&mut rust_encs, &rust_info, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
                .into_vec()
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
            let mut rust_encs: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let rust_info = AttributeRekeyInfo::from(&info);
            let result = rekey_batch(&mut rust_encs, &rust_info, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
            return Ok(result
                .into_vec()
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
#[pyo3(name = "transcrypt_batch")]
#[allow(clippy::expect_used)]
pub fn py_transcrypt_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyTranscryptionInfo,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();
    let transcryption_info = TranscryptionInfo::from(info);

    // Try EncryptedPseudonym
    if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
        let mut rust_encs: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedPseudonym>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let result = transcrypt_batch(&mut rust_encs, &transcryption_info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_vec()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    // Try EncryptedAttribute
    if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
        let mut rust_encs: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedAttribute>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let result = transcrypt_batch(&mut rust_encs, &transcryption_info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_vec()
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
        let mut rust_encs: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedRecord>()
                    .expect("type already validated")
                    .0
                    .clone()
            })
            .collect();
        let result = transcrypt_batch(&mut rust_encs, &transcryption_info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_vec()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedRecord(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    // Try EncryptedPEPJSONValue
    #[cfg(feature = "json")]
    if encrypted[0].extract::<PyEncryptedPEPJSONValue>().is_ok() {
        let mut rust_encs: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedPEPJSONValue>()
                    .expect("type already validated")
                    .0
                    .clone()
            })
            .collect();
        let result = transcrypt_batch(&mut rust_encs, &transcryption_info, &mut rng)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))?;
        return Ok(result
            .into_vec()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPEPJSONValue(e))
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
