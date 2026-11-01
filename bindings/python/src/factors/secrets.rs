//! Python bindings for the secrets from which factors are derived.

use libpep::factors::derivation::MAX_INPUT_LENGTH;
use libpep::factors::{PseudonymizationSecret, RekeyingSecret};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// The factor derivation needs the secret shorter than 2^16 bytes.
fn checked(data: Vec<u8>) -> PyResult<Vec<u8>> {
    if data.len() >= MAX_INPUT_LENGTH {
        return Err(PyValueError::new_err(format!(
            "a secret must be shorter than {MAX_INPUT_LENGTH} bytes"
        )));
    }
    Ok(data)
}

/// Pseudonymization secret used to derive reshuffle factors from pseudonymization domains.
/// A secret is a byte array of arbitrary length.
#[derive(Clone, Debug)]
#[pyclass(name = "PseudonymizationSecret", from_py_object)]
pub struct PyPseudonymizationSecret(pub(crate) PseudonymizationSecret);

#[pymethods]
impl PyPseudonymizationSecret {
    #[new]
    fn new(data: Vec<u8>) -> PyResult<Self> {
        Ok(Self(PseudonymizationSecret::from(checked(data)?)))
    }
}

/// Rekeying secret used to derive rekey factors from encryption contexts.
/// A secret is a byte array of arbitrary length.
#[derive(Clone, Debug)]
#[pyclass(name = "RekeyingSecret", from_py_object)]
pub struct PyRekeyingSecret(pub(crate) RekeyingSecret);

#[pymethods]
impl PyRekeyingSecret {
    #[new]
    fn new(data: Vec<u8>) -> PyResult<Self> {
        Ok(Self(RekeyingSecret::from(checked(data)?)))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymizationSecret>()?;
    m.add_class::<PyRekeyingSecret>()?;
    Ok(())
}
