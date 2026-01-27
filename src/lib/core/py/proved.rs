//! Python bindings for verifiable proofs.

use crate::core::proved::{RSKFactorsProof, VerifiableRSK, VerifiableRekey, VerifiableReshuffle};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// A verifiable proof for reshuffle operations.
#[pyclass(name = "VerifiableReshuffle")]
#[derive(Clone)]
pub struct PyVerifiableReshuffle {
    pub(crate) inner: VerifiableReshuffle,
}

#[pymethods]
impl PyVerifiableReshuffle {
    /// Serialize to JSON string.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from JSON string.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("Failed to deserialize: {}", e)))
    }
}

/// A verifiable proof for rekey operations.
#[pyclass(name = "VerifiableRekey")]
#[derive(Clone)]
pub struct PyVerifiableRekey {
    pub(crate) inner: VerifiableRekey,
}

#[pymethods]
impl PyVerifiableRekey {
    /// Serialize to JSON string.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from JSON string.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("Failed to deserialize: {}", e)))
    }
}

/// A verifiable proof for RSK (reshuffle-shift-rekey) operations.
#[pyclass(name = "VerifiableRSK")]
#[derive(Clone)]
pub struct PyVerifiableRSK {
    pub(crate) inner: VerifiableRSK,
}

#[pymethods]
impl PyVerifiableRSK {
    /// Serialize to JSON string.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from JSON string.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("Failed to deserialize: {}", e)))
    }
}

/// A proof for RSK factors.
#[pyclass(name = "RSKFactorsProof")]
#[derive(Clone)]
pub struct PyRSKFactorsProof {
    pub(crate) inner: RSKFactorsProof,
}

#[pymethods]
impl PyRSKFactorsProof {
    /// Serialize to JSON string.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from JSON string.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("Failed to deserialize: {}", e)))
    }
}

/// Register the proved module.
pub fn register_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifiableReshuffle>()?;
    parent_module.add_class::<PyVerifiableRekey>()?;
    parent_module.add_class::<PyVerifiableRSK>()?;
    parent_module.add_class::<PyRSKFactorsProof>()?;
    Ok(())
}
