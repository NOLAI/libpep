//! Python bindings for commitment types.

use crate::factors::{VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment};
use pyo3::prelude::*;

#[cfg(feature = "serde")]
use pyo3::exceptions::PyValueError;

/// Pseudonymization factor commitments with proofs (Python).
#[pyclass(name = "VerifiablePseudonymizationCommitments", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiablePseudonymizationCommitments {
    pub(crate) inner: VerifiablePseudonymizationCommitment,
}

#[pymethods]
impl PyVerifiablePseudonymizationCommitments {
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
            .map(|inner| PyVerifiablePseudonymizationCommitments { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<VerifiablePseudonymizationCommitment> for PyVerifiablePseudonymizationCommitments {
    fn from(inner: VerifiablePseudonymizationCommitment) -> Self {
        PyVerifiablePseudonymizationCommitments { inner }
    }
}

/// Rekey factor commitments with proof (Python).
#[pyclass(name = "VerifiableRekeyCommitments", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRekeyCommitments {
    pub(crate) inner: VerifiableRekeyCommitment,
}

#[pymethods]
impl PyVerifiableRekeyCommitments {
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
            .map(|inner| PyVerifiableRekeyCommitments { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<VerifiableRekeyCommitment> for PyVerifiableRekeyCommitments {
    fn from(inner: VerifiableRekeyCommitment) -> Self {
        PyVerifiableRekeyCommitments { inner }
    }
}

#[allow(dead_code)]
pub(crate) fn register_commitment_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifiablePseudonymizationCommitments>()?;
    parent_module.add_class::<PyVerifiableRekeyCommitments>()?;
    Ok(())
}
