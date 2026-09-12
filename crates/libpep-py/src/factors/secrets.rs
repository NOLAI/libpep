//! Python bindings for the secrets from which factors are derived.

use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use pyo3::prelude::*;

/// Pseudonymization secret used to derive reshuffle factors from pseudonymization domains.
/// A secret is a byte array of arbitrary length.
#[derive(Clone, Debug)]
#[pyclass(name = "PseudonymizationSecret", from_py_object)]
pub struct PyPseudonymizationSecret(pub(crate) PseudonymizationSecret);

#[pymethods]
impl PyPseudonymizationSecret {
    #[new]
    fn new(data: Vec<u8>) -> Self {
        Self(PseudonymizationSecret::from(data))
    }

    #[staticmethod]
    #[pyo3(name = "from")]
    fn py_from(data: Vec<u8>) -> Self {
        Self(PseudonymizationSecret::from(data))
    }
}

/// Encryption secret used to derive rekey factors from encryption contexts.
/// A secret is a byte array of arbitrary length.
#[derive(Clone, Debug)]
#[pyclass(name = "EncryptionSecret", from_py_object)]
pub struct PyEncryptionSecret(pub(crate) EncryptionSecret);

#[pymethods]
impl PyEncryptionSecret {
    #[new]
    fn new(data: Vec<u8>) -> Self {
        Self(EncryptionSecret::from(data))
    }

    #[staticmethod]
    #[pyo3(name = "from")]
    fn py_from(data: Vec<u8>) -> Self {
        Self(EncryptionSecret::from(data))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymizationSecret>()?;
    m.add_class::<PyEncryptionSecret>()?;
    Ok(())
}
