//! Python bindings for deriving factors from secrets, sessions and domains within a protocol
//! context.

use crate::factors::secrets::{PyEncryptionSecret, PyPseudonymizationSecret};
use crate::factors::types::{PyAttributeRekeyFactor, PyPseudonymRekeyFactor, PyReshuffleFactor};
use crate::protocol::{context_or_default, PyContext};
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
};
use pyo3::prelude::*;

/// Derive the pseudonym rekey factor of a session from an encryption secret within the protocol
/// `context` (the default context if omitted).
#[pyfunction]
#[pyo3(name = "make_pseudonym_rekey_factor", signature = (secret, session, context = None))]
pub fn py_make_pseudonym_rekey_factor(
    secret: &PyEncryptionSecret,
    session: &str,
    context: Option<&PyContext>,
) -> PyPseudonymRekeyFactor {
    make_pseudonym_rekey_factor(
        &secret.0,
        &EncryptionContext::from(session),
        &context_or_default(context),
    )
    .into()
}

/// Derive the attribute rekey factor of a session from an encryption secret within the protocol
/// `context` (the default context if omitted).
#[pyfunction]
#[pyo3(name = "make_attribute_rekey_factor", signature = (secret, session, context = None))]
pub fn py_make_attribute_rekey_factor(
    secret: &PyEncryptionSecret,
    session: &str,
    context: Option<&PyContext>,
) -> PyAttributeRekeyFactor {
    make_attribute_rekey_factor(
        &secret.0,
        &EncryptionContext::from(session),
        &context_or_default(context),
    )
    .into()
}

/// Derive the reshuffle factor of a domain from a pseudonymization secret within the protocol
/// `context` (the default context if omitted).
#[pyfunction]
#[pyo3(name = "make_pseudonymisation_factor", signature = (secret, domain, context = None))]
pub fn py_make_pseudonymisation_factor(
    secret: &PyPseudonymizationSecret,
    domain: &str,
    context: Option<&PyContext>,
) -> PyReshuffleFactor {
    make_pseudonymisation_factor(
        &secret.0,
        &PseudonymizationDomain::from(domain),
        &context_or_default(context),
    )
    .into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_make_pseudonym_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_rekey_factor, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonymisation_factor, m)?)?;
    Ok(())
}
