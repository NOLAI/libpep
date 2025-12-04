use super::data::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::core::long::rerandomize::{rerandomize_long_attribute, rerandomize_long_pseudonym};
use crate::core::long::transcryption::{
    pseudonymize_long, rekey_long_attribute, rekey_long_pseudonym, transcrypt_long_attribute,
    transcrypt_long_pseudonym,
};
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::core::transcryption::py::contexts::{
    PyAttributeRekeyInfo, PyPseudonymRekeyFactor, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use pyo3::prelude::*;

#[cfg(not(feature = "elgamal3"))]
use crate::core::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey};
#[cfg(not(feature = "elgamal3"))]
use crate::core::py::keys::{PyAttributeSessionPublicKey, PyPseudonymSessionPublicKey};

/// Rerandomize a long encrypted pseudonym.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize_long_pseudonym")]
pub fn py_rerandomize_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
) -> PyLongEncryptedPseudonym {
    let mut rng = rand::rng();
    PyLongEncryptedPseudonym(rerandomize_long_pseudonym(&encrypted.0, &mut rng))
}

/// Rerandomize a long encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize_long_pseudonym")]
pub fn py_rerandomize_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
    public_key: &PyPseudonymSessionPublicKey,
) -> PyLongEncryptedPseudonym {
    let mut rng = rand::rng();
    PyLongEncryptedPseudonym(rerandomize_long_pseudonym(
        &encrypted.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Rerandomize a long encrypted attribute.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize_long_attribute")]
pub fn py_rerandomize_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
) -> PyLongEncryptedAttribute {
    let mut rng = rand::rng();
    PyLongEncryptedAttribute(rerandomize_long_attribute(&encrypted.0, &mut rng))
}

/// Rerandomize a long encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize_long_attribute")]
pub fn py_rerandomize_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
    public_key: &PyAttributeSessionPublicKey,
) -> PyLongEncryptedAttribute {
    let mut rng = rand::rng();
    PyLongEncryptedAttribute(rerandomize_long_attribute(
        &encrypted.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Pseudonymize a long encrypted pseudonym.
#[pyfunction]
#[pyo3(name = "pseudonymize_long")]
pub fn py_pseudonymize_long(
    encrypted: &PyLongEncryptedPseudonym,
    pseudonymization_info: &PyPseudonymizationInfo,
) -> PyLongEncryptedPseudonym {
    let info = PseudonymizationInfo::from(pseudonymization_info);
    PyLongEncryptedPseudonym(pseudonymize_long(&encrypted.0, &info))
}

/// Rekey a long encrypted pseudonym.
#[pyfunction]
#[pyo3(name = "rekey_long_pseudonym")]
pub fn py_rekey_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
    rekey_factor: &PyPseudonymRekeyFactor,
) -> PyLongEncryptedPseudonym {
    PyLongEncryptedPseudonym(rekey_long_pseudonym(&encrypted.0, &rekey_factor.0))
}

/// Rekey a long encrypted attribute.
#[pyfunction]
#[pyo3(name = "rekey_long_attribute")]
pub fn py_rekey_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
    rekey_info: &PyAttributeRekeyInfo,
) -> PyLongEncryptedAttribute {
    let info = AttributeRekeyInfo::from(rekey_info);
    PyLongEncryptedAttribute(rekey_long_attribute(&encrypted.0, &info))
}

/// Transcrypt a long encrypted pseudonym.
#[pyfunction]
#[pyo3(name = "transcrypt_long_pseudonym")]
pub fn py_transcrypt_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
    transcryption_info: &PyTranscryptionInfo,
) -> PyLongEncryptedPseudonym {
    let info = TranscryptionInfo::from(transcryption_info);
    PyLongEncryptedPseudonym(transcrypt_long_pseudonym(&encrypted.0, &info))
}

/// Transcrypt a long encrypted attribute.
#[pyfunction]
#[pyo3(name = "transcrypt_long_attribute")]
pub fn py_transcrypt_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
    transcryption_info: &PyTranscryptionInfo,
) -> PyLongEncryptedAttribute {
    let info = TranscryptionInfo::from(transcryption_info);
    PyLongEncryptedAttribute(transcrypt_long_attribute(&encrypted.0, &info))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_rerandomize_long_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_rerandomize_long_attribute, m)?)?;
    m.add_function(wrap_pyfunction!(py_pseudonymize_long, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_long_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_long_attribute, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_long_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_long_attribute, m)?)?;
    Ok(())
}
