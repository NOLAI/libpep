//! Python bindings for commitment types.

use crate::factors::{
    ProvedPseudonymizationCommitments, ProvedRekeyCommitments, ProvedReshuffleCommitments,
};
use pyo3::prelude::*;

#[cfg(feature = "serde")]
use pyo3::exceptions::PyValueError;

/// Pseudonymization factor commitments with proofs (Python).
#[pyclass(name = "ProvedPseudonymizationCommitments")]
#[derive(Clone)]
pub struct PyProvedPseudonymizationCommitments {
    pub(crate) inner: ProvedPseudonymizationCommitments,
}

#[pymethods]
impl PyProvedPseudonymizationCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| PyProvedPseudonymizationCommitments { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<ProvedPseudonymizationCommitments> for PyProvedPseudonymizationCommitments {
    fn from(inner: ProvedPseudonymizationCommitments) -> Self {
        PyProvedPseudonymizationCommitments { inner }
    }
}

/// Reshuffle factor commitments with proof (Python).
#[pyclass(name = "ProvedReshuffleCommitments")]
#[derive(Clone)]
pub struct PyProvedReshuffleCommitments {
    pub(crate) inner: ProvedReshuffleCommitments,
}

#[pymethods]
impl PyProvedReshuffleCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| PyProvedReshuffleCommitments { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<ProvedReshuffleCommitments> for PyProvedReshuffleCommitments {
    fn from(inner: ProvedReshuffleCommitments) -> Self {
        PyProvedReshuffleCommitments { inner }
    }
}

/// Rekey factor commitments with proof (Python).
#[pyclass(name = "ProvedRekeyCommitments")]
#[derive(Clone)]
pub struct PyProvedRekeyCommitments {
    pub(crate) inner: ProvedRekeyCommitments,
}

#[pymethods]
impl PyProvedRekeyCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| PyProvedRekeyCommitments { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<ProvedRekeyCommitments> for PyProvedRekeyCommitments {
    fn from(inner: ProvedRekeyCommitments) -> Self {
        PyProvedRekeyCommitments { inner }
    }
}

pub(crate) fn register_commitment_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyProvedPseudonymizationCommitments>()?;
    parent_module.add_class::<PyProvedReshuffleCommitments>()?;
    parent_module.add_class::<PyProvedRekeyCommitments>()?;
    Ok(())
}
