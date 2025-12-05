//! Python bindings for factor derivation functions.
//!
//! Note: The secret types (PseudonymizationSecret, EncryptionSecret) are defined in
//! core/py/keys.rs and the factor types are defined in contexts.rs.
//! This module provides standalone functions for deriving factors from secrets and contexts.

use crate::core::py::keys::{PyEncryptionSecret, PyPseudonymizationSecret};
use crate::core::transcryption::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::core::transcryption::secrets::*;
use pyo3::prelude::*;

use super::contexts::{PyAttributeRekeyFactor, PyPseudonymRekeyFactor, PyReshuffleFactor};

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
