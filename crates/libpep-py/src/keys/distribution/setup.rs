use super::blinding::{
    PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalKeys, PyBlindedPseudonymGlobalSecretKey,
    PyBlindingFactor,
};
use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::keys::distribution::*;
use crate::keys::py::types::{
    PyAttributeGlobalPublicKey, PyGlobalPublicKeys, PyPseudonymGlobalPublicKey,
};
use pyo3::prelude::*;

#[pyfunction]
#[pyo3(name = "make_distributed_pseudonym_global_keys")]
pub fn py_make_distributed_pseudonym_global_keys(
    n: usize,
) -> (
    PyPseudonymGlobalPublicKey,
    PyBlindedPseudonymGlobalSecretKey,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_pseudonym_global_keys(n, &mut rng);

    (
        PyPseudonymGlobalPublicKey(PyGroupElement(public_key.0)),
        PyBlindedPseudonymGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

/// Setup a distributed system with attribute global keys.
#[pyfunction]
#[pyo3(name = "make_distributed_attribute_global_keys")]
pub fn py_make_distributed_attribute_global_keys(
    n: usize,
) -> (
    PyAttributeGlobalPublicKey,
    PyBlindedAttributeGlobalSecretKey,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_attribute_global_keys(n, &mut rng);

    (
        PyAttributeGlobalPublicKey(PyGroupElement(public_key.0)),
        PyBlindedAttributeGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

/// Setup a distributed system with both global keys.
#[pyfunction]
#[pyo3(name = "make_distributed_global_keys")]
pub fn py_make_distributed_global_keys(
    n: usize,
) -> (
    PyGlobalPublicKeys,
    PyBlindedGlobalKeys,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::rng();
    let (global_public_keys, blinded_keys, blinding_factors) =
        make_distributed_global_keys(n, &mut rng);

    (
        PyGlobalPublicKeys {
            pseudonym: PyPseudonymGlobalPublicKey(PyGroupElement(global_public_keys.pseudonym.0)),
            attribute: PyAttributeGlobalPublicKey(PyGroupElement(global_public_keys.attribute.0)),
        },
        PyBlindedGlobalKeys {
            pseudonym: PyBlindedPseudonymGlobalSecretKey(blinded_keys.pseudonym),
            attribute: PyBlindedAttributeGlobalSecretKey(blinded_keys.attribute),
        },
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
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
