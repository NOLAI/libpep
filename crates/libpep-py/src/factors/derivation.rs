//! Python bindings for deriving factors from secrets and contexts.

use crate::factors::secrets::{PyEncryptionSecret, PyPseudonymizationSecret};
use crate::factors::types::{PyAttributeRekeyFactor, PyPseudonymRekeyFactor, PyReshuffleFactor};
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
};
use pyo3::prelude::*;

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
    m.add_function(wrap_pyfunction!(py_make_pseudonym_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonymisation_factor, m)?)?;
    Ok(())
}
