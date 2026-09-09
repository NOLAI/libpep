//! Python bindings for secret types and factor derivation functions.

use crate::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::factors::*;
use pyo3::prelude::*;

use crate::factors::py::types::{
    PyAttributeRekeyFactor, PyPseudonymRekeyFactor, PyReshuffleFactor,
};

// Re-export the secret types from keys::py::types to avoid duplicate definitions
pub use crate::keys::py::types::{PyEncryptionSecret, PyPseudonymizationSecret};

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
    // Register the secret classes (defined in keys module but re-exported here)
    m.add_class::<PyPseudonymizationSecret>()?;
    m.add_class::<PyEncryptionSecret>()?;

    // Register the factory functions
    m.add_function(wrap_pyfunction!(py_make_pseudonym_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonymisation_factor, m)?)?;
    Ok(())
}
