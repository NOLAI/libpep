//! Python bindings for commitment types.

use crate::factors::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
use pyo3::prelude::*;

#[cfg(feature = "serde")]
use pyo3::exceptions::PyValueError;

/// Pseudonymization factor commitment for a single transition (Python).
#[pyclass(name = "VerifiablePseudonymizationCommitment", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiablePseudonymizationCommitment {
    pub(crate) inner: VerifiablePseudonymizationCommitment,
}

#[pymethods]
impl PyVerifiablePseudonymizationCommitment {
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
            .map(|inner| PyVerifiablePseudonymizationCommitment { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<VerifiablePseudonymizationCommitment> for PyVerifiablePseudonymizationCommitment {
    fn from(inner: VerifiablePseudonymizationCommitment) -> Self {
        PyVerifiablePseudonymizationCommitment { inner }
    }
}

/// Rekey factor commitment for a single transition (Python).
#[pyclass(name = "VerifiableRekeyCommitment", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRekeyCommitment {
    pub(crate) inner: VerifiableRekeyCommitment,
}

#[pymethods]
impl PyVerifiableRekeyCommitment {
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
            .map(|inner| PyVerifiableRekeyCommitment { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<VerifiableRekeyCommitment> for PyVerifiableRekeyCommitment {
    fn from(inner: VerifiableRekeyCommitment) -> Self {
        PyVerifiableRekeyCommitment { inner }
    }
}

/// Combined transcryption commitments — pseudonymization (reshuffle + rekey)
/// plus attribute rekey — for a transition (Python).
#[pyclass(name = "VerifiableTranscryptionCommitment", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableTranscryptionCommitment {
    pub(crate) inner: VerifiableTranscryptionCommitment,
}

#[pymethods]
impl PyVerifiableTranscryptionCommitment {
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
            .map(|inner| PyVerifiableTranscryptionCommitment { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<VerifiableTranscryptionCommitment> for PyVerifiableTranscryptionCommitment {
    fn from(inner: VerifiableTranscryptionCommitment) -> Self {
        PyVerifiableTranscryptionCommitment { inner }
    }
}

#[allow(dead_code)]
pub(crate) fn register_commitment_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifiablePseudonymizationCommitment>()?;
    parent_module.add_class::<PyVerifiableRekeyCommitment>()?;
    parent_module.add_class::<PyVerifiableTranscryptionCommitment>()?;
    Ok(())
}
