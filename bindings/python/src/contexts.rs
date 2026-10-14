//! Python bindings for pseudonymization domains and encryption contexts.

use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use pyo3::prelude::*;

/// The domain a pseudonym exists in (typically a user's role or usergroup).
#[derive(Clone, Debug)]
#[pyclass(name = "PseudonymizationDomain", from_py_object)]
pub struct PyPseudonymizationDomain(pub(crate) PseudonymizationDomain);

#[pymethods]
impl PyPseudonymizationDomain {
    /// Create a specific pseudonymization domain from a string identifier.
    #[new]
    fn new(payload: &str) -> Self {
        Self(PseudonymizationDomain::from(payload))
    }

    /// Create a specific pseudonymization domain from a string identifier.
    #[staticmethod]
    fn from_str(payload: &str) -> Self {
        Self(PseudonymizationDomain::from(payload))
    }

    /// Create a global pseudonymization domain. Named with a trailing underscore because
    /// `global` is a Python keyword.
    #[cfg(feature = "global-pseudonyms")]
    #[staticmethod]
    #[pyo3(name = "global_")]
    fn global() -> Self {
        Self(PseudonymizationDomain::global())
    }
}

/// The context a ciphertext exists in (typically a user's session).
#[derive(Clone, Debug)]
#[pyclass(name = "EncryptionContext", from_py_object)]
pub struct PyEncryptionContext(pub(crate) EncryptionContext);

#[pymethods]
impl PyEncryptionContext {
    /// Create a specific encryption context from a string identifier.
    #[new]
    fn new(payload: &str) -> Self {
        Self(EncryptionContext::from(payload))
    }

    /// Create a specific encryption context from a string identifier.
    #[staticmethod]
    fn from_str(payload: &str) -> Self {
        Self(EncryptionContext::from(payload))
    }

    /// Create a global encryption context. Named with a trailing underscore because `global`
    /// is a Python keyword.
    #[cfg(feature = "offline")]
    #[staticmethod]
    #[pyo3(name = "global_")]
    fn global() -> Self {
        Self(EncryptionContext::global())
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymizationDomain>()?;
    m.add_class::<PyEncryptionContext>()?;
    Ok(())
}
