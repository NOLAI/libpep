use super::blinding::{
    PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalSecretKeys,
    PyBlindedPseudonymGlobalSecretKey, PyBlindingFactor,
};
use crate::elgamal::arithmetic::group_elements::PyGroupElement;
use crate::keys::types::{
    PyAttributeGlobalPublicKey, PyGlobalPublicKeys, PyPseudonymGlobalPublicKey,
};
use libpep::keys::distribution::*;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// A distributed system needs at least one transcryptor.
fn checked(n: usize) -> PyResult<usize> {
    if n == 0 {
        return Err(PyValueError::new_err(
            "a distributed system needs at least one transcryptor",
        ));
    }
    Ok(n)
}

#[pyfunction]
#[pyo3(name = "make_distributed_pseudonym_global_keys")]
pub fn py_make_distributed_pseudonym_global_keys(
    n: usize,
) -> PyResult<(
    PyPseudonymGlobalPublicKey,
    PyBlindedPseudonymGlobalSecretKey,
    Vec<PyBlindingFactor>,
)> {
    let n = checked(n)?;
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_pseudonym_global_keys(n, &mut rng);

    Ok((
        PyPseudonymGlobalPublicKey(PyGroupElement(*public_key)),
        PyBlindedPseudonymGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    ))
}

/// Setup a distributed system with attribute global keys.
#[pyfunction]
#[pyo3(name = "make_distributed_attribute_global_keys")]
pub fn py_make_distributed_attribute_global_keys(
    n: usize,
) -> PyResult<(
    PyAttributeGlobalPublicKey,
    PyBlindedAttributeGlobalSecretKey,
    Vec<PyBlindingFactor>,
)> {
    let n = checked(n)?;
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_attribute_global_keys(n, &mut rng);

    Ok((
        PyAttributeGlobalPublicKey(PyGroupElement(*public_key)),
        PyBlindedAttributeGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    ))
}

/// Setup a distributed system with both global keys.
#[pyfunction]
#[pyo3(name = "make_distributed_global_keys")]
pub fn py_make_distributed_global_keys(
    n: usize,
) -> PyResult<(
    PyGlobalPublicKeys,
    PyBlindedGlobalSecretKeys,
    Vec<PyBlindingFactor>,
)> {
    let n = checked(n)?;
    let mut rng = rand::rng();
    let (global_public_keys, blinded_keys, blinding_factors) =
        make_distributed_global_keys(n, &mut rng);

    Ok((
        PyGlobalPublicKeys {
            pseudonym: PyPseudonymGlobalPublicKey(PyGroupElement(*global_public_keys.pseudonym)),
            attribute: PyAttributeGlobalPublicKey(PyGroupElement(*global_public_keys.attribute)),
        },
        PyBlindedGlobalSecretKeys {
            pseudonym: PyBlindedPseudonymGlobalSecretKey(blinded_keys.pseudonym),
            attribute: PyBlindedAttributeGlobalSecretKey(blinded_keys.attribute),
        },
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(
        py_make_distributed_pseudonym_global_keys,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        py_make_distributed_attribute_global_keys,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(py_make_distributed_global_keys, m)?)?;
    Ok(())
}
