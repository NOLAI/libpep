use super::data::{PyEncryptedAttribute, PyEncryptedPseudonym};
#[cfg(not(feature = "elgamal3"))]
use super::keys::{PyAttributeSessionPublicKey, PyPseudonymSessionPublicKey};
use crate::arithmetic::py::PyScalarNonZero;
#[cfg(not(feature = "elgamal3"))]
use crate::core::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey};
use crate::core::transcryption::contexts::RerandomizeFactor;
use pyo3::prelude::*;

/// Rerandomize an encrypted pseudonym.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_pseudonym")]
pub fn py_rerandomize_encrypted_pseudonym(v: &PyEncryptedPseudonym) -> PyEncryptedPseudonym {
    let mut rng = rand::rng();
    crate::core::rerandomize::rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize an encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_pseudonym")]
pub fn py_rerandomize_encrypted_pseudonym(
    v: &PyEncryptedPseudonym,
    public_key: &PyPseudonymSessionPublicKey,
) -> PyEncryptedPseudonym {
    let mut rng = rand::rng();
    crate::core::rerandomize::rerandomize(
        &v.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Rerandomize an encrypted attribute.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_attribute")]
pub fn py_rerandomize_encrypted_attribute(v: &PyEncryptedAttribute) -> PyEncryptedAttribute {
    let mut rng = rand::rng();
    crate::core::rerandomize::rerandomize(&v.0, &mut rng).into()
}

/// Rerandomize an encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_attribute")]
pub fn py_rerandomize_encrypted_attribute(
    v: &PyEncryptedAttribute,
    public_key: &PyAttributeSessionPublicKey,
) -> PyEncryptedAttribute {
    let mut rng = rand::rng();
    crate::core::rerandomize::rerandomize(
        &v.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_pseudonym_known")]
pub fn py_rerandomize_encrypted_pseudonym_known(
    v: &PyEncryptedPseudonym,
    r: &PyScalarNonZero,
) -> PyEncryptedPseudonym {
    crate::core::rerandomize::rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_pseudonym_known")]
pub fn py_rerandomize_encrypted_pseudonym_known(
    v: &PyEncryptedPseudonym,
    public_key: &PyPseudonymSessionPublicKey,
    r: &PyScalarNonZero,
) -> PyEncryptedPseudonym {
    crate::core::rerandomize::rerandomize_known(
        &v.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &RerandomizeFactor(r.0),
    )
    .into()
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_attribute_known")]
pub fn py_rerandomize_encrypted_attribute_known(
    v: &PyEncryptedAttribute,
    r: &PyScalarNonZero,
) -> PyEncryptedAttribute {
    crate::core::rerandomize::rerandomize_known(&v.0, &RerandomizeFactor(r.0)).into()
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize_encrypted_attribute_known")]
pub fn py_rerandomize_encrypted_attribute_known(
    v: &PyEncryptedAttribute,
    public_key: &PyAttributeSessionPublicKey,
    r: &PyScalarNonZero,
) -> PyEncryptedAttribute {
    crate::core::rerandomize::rerandomize_known(
        &v.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &RerandomizeFactor(r.0),
    )
    .into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_rerandomize_encrypted_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_rerandomize_encrypted_attribute, m)?)?;
    m.add_function(wrap_pyfunction!(
        py_rerandomize_encrypted_pseudonym_known,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        py_rerandomize_encrypted_attribute_known,
        m
    )?)?;
    Ok(())
}
