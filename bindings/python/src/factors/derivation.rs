//! Python bindings for deriving factors from secrets, sessions and domains within a protocol
//! context.

use crate::contexts::{PyEncryptionContext, PyPseudonymizationDomain};
use crate::factors::secrets::{PyEncryptionSecret, PyPseudonymizationSecret};
use crate::factors::types::{PyAttributeRekeyFactor, PyPseudonymRekeyFactor, PyReshuffleFactor};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymization_factor,
};
use pyo3::prelude::*;

/// Derive the pseudonym rekey factor of a session from an encryption secret.
#[pyfunction]
#[pyo3(name = "make_pseudonym_rekey_factor", signature = (secret, session))]
pub fn py_make_pseudonym_rekey_factor(
    secret: &PyEncryptionSecret,
    session: &PyEncryptionContext,
) -> PyPseudonymRekeyFactor {
    make_pseudonym_rekey_factor(&secret.0, &session.0).into()
}

/// Derive the attribute rekey factor of a session from an encryption secret.
#[pyfunction]
#[pyo3(name = "make_attribute_rekey_factor", signature = (secret, session))]
pub fn py_make_attribute_rekey_factor(
    secret: &PyEncryptionSecret,
    session: &PyEncryptionContext,
) -> PyAttributeRekeyFactor {
    make_attribute_rekey_factor(&secret.0, &session.0).into()
}

/// Derive the reshuffle factor of a domain from a pseudonymization secret.
#[pyfunction]
#[pyo3(name = "make_pseudonymization_factor", signature = (secret, domain))]
pub fn py_make_pseudonymization_factor(
    secret: &PyPseudonymizationSecret,
    domain: &PyPseudonymizationDomain,
) -> PyReshuffleFactor {
    make_pseudonymization_factor(&secret.0, &domain.0).into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_make_pseudonym_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonymization_factor, m)?)?;
    Ok(())
}
