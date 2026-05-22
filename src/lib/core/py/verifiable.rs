//! Python bindings for verifiable proofs.

use crate::core::verifiable::{VerifiableRRSK, VerifiableRekey, VerifiableReshuffle};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// A verifiable proof for reshuffle operations.
#[pyclass(name = "VerifiableReshuffle", from_py_object)]
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
#[pyclass(name = "VerifiableRekey", from_py_object)]
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

/// A verifiable proof for RRSK (rerandomize + reshuffle + rekey) operations.
/// Used for verifiable pseudonymization, which always rerandomizes alongside
/// the reshuffle/rekey to keep ciphertexts unlinkable.
#[pyclass(name = "VerifiableRSK", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRSK {
    pub(crate) inner: VerifiableRRSK,
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

/// Register the verifiable module.
pub fn register_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifiableReshuffle>()?;
    parent_module.add_class::<PyVerifiableRekey>()?;
    parent_module.add_class::<PyVerifiableRSK>()?;
    Ok(())
}
