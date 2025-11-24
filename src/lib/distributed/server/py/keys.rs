use super::super::keys::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_shares,
};
use super::setup::PyBlindingFactor;
use crate::arithmetic::py::PyScalarNonZero;
use crate::core::transcryption::contexts::{AttributeRekeyFactor, PseudonymRekeyFactor};
use crate::distributed::client::py::keys::{
    PyAttributeSessionKeyShare, PyPseudonymSessionKeyShare, PySessionKeyShares,
};
use pyo3::prelude::*;

/// Create a pseudonym session key share.
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_key_share")]
pub fn py_make_pseudonym_session_key_share(
    rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PyPseudonymSessionKeyShare {
    PyPseudonymSessionKeyShare(make_pseudonym_session_key_share(
        &PseudonymRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Create an attribute session key share.
#[pyfunction]
#[pyo3(name = "make_attribute_session_key_share")]
pub fn py_make_attribute_session_key_share(
    rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PyAttributeSessionKeyShare {
    PyAttributeSessionKeyShare(make_attribute_session_key_share(
        &AttributeRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Create session key shares.
#[pyfunction]
#[pyo3(name = "make_session_key_shares")]
pub fn py_make_session_key_shares(
    pseudonym_rekey_factor: &PyScalarNonZero,
    attribute_rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PySessionKeyShares {
    let shares = make_session_key_shares(
        &PseudonymRekeyFactor::from(pseudonym_rekey_factor.0),
        &AttributeRekeyFactor::from(attribute_rekey_factor.0),
        &blinding_factor.0,
    );
    PySessionKeyShares {
        pseudonym: PyPseudonymSessionKeyShare(shares.pseudonym),
        attribute: PyAttributeSessionKeyShare(shares.attribute),
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_key_share, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_key_share, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_key_shares, m)?)?;
    Ok(())
}
