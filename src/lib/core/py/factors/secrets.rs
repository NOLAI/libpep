//! Python bindings for secret types and factor derivation functions.

use crate::core::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::core::factors::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::core::factors::*;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

use crate::core::py::factors::types::{
    PyAttributeRekeyFactor, PyPseudonymRekeyFactor, PyReshuffleFactor,
};

/// Pseudonymization secret used to derive a reshuffle factor from a pseudonymization domain.
#[derive(Clone, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymizationSecret")]
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

/// Encryption secret used to derive rekey factors from an encryption context.
#[derive(Clone, Debug, From, Into, Deref)]
#[pyclass(name = "EncryptionSecret")]
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

/// Derive a pseudonym rekey factor from a secret and a context.
#[pyfunction]
#[pyo3(name = "make_pseudonym_rekey_factor")]
pub fn py_make_pseudonym_rekey_factor(
    secret: &PyEncryptionSecret,
    context: &str,
) -> PyPseudonymRekeyFactor {
    make_pseudonym_rekey_factor(&secret.0, &EncryptionContext::from(context)).into()
}

/// Derive an attribute rekey factor from a secret and a context.
#[pyfunction]
#[pyo3(name = "make_attribute_rekey_factor")]
pub fn py_make_attribute_rekey_factor(
    secret: &PyEncryptionSecret,
    context: &str,
) -> PyAttributeRekeyFactor {
    make_attribute_rekey_factor(&secret.0, &EncryptionContext::from(context)).into()
}

/// Derive a pseudonymisation factor from a secret and a domain.
#[pyfunction]
#[pyo3(name = "make_pseudonymisation_factor")]
pub fn py_make_pseudonymisation_factor(
    secret: &PyPseudonymizationSecret,
    domain: &str,
) -> PyReshuffleFactor {
    make_pseudonymisation_factor(&secret.0, &PseudonymizationDomain::from(domain)).into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymizationSecret>()?;
    m.add_class::<PyEncryptionSecret>()?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonymisation_factor, m)?)?;
    Ok(())
}
