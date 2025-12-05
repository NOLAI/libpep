use super::contexts::{
    PyAttributeRekeyInfo, PyPseudonymRekeyFactor, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use crate::core::data::{
    decrypt_attribute, decrypt_pseudonym, encrypt_attribute, encrypt_pseudonym,
};
use crate::core::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use crate::core::py::data::{PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym};
use crate::core::py::keys::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey,
};
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::core::transcryption::ops::{
    pseudonymize, rekey_attribute, rekey_pseudonym, transcrypt_attribute, transcrypt_pseudonym,
};
use pyo3::prelude::*;

/// Encrypt a [`PyPseudonym`] using a [`PyPseudonymSessionPublicKey`].
#[pyfunction]
#[pyo3(name = "encrypt_pseudonym")]
pub fn py_encrypt_pseudonym(
    m: &PyPseudonym,
    public_key: &PyPseudonymSessionPublicKey,
) -> PyEncryptedPseudonym {
    let mut rng = rand::rng();
    encrypt_pseudonym(
        &m.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an [`PyEncryptedPseudonym`] using a [`PyPseudonymSessionSecretKey`].
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_pseudonym")]
pub fn py_decrypt_pseudonym(
    v: &PyEncryptedPseudonym,
    secret_key: &PyPseudonymSessionSecretKey,
) -> Option<PyPseudonym> {
    decrypt_pseudonym(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an [`PyEncryptedPseudonym`] using a [`PyPseudonymSessionSecretKey`].
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_pseudonym")]
pub fn py_decrypt_pseudonym(
    v: &PyEncryptedPseudonym,
    secret_key: &PyPseudonymSessionSecretKey,
) -> PyPseudonym {
    decrypt_pseudonym(&v.0, &PseudonymSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Encrypt an [`PyAttribute`] using a [`PyAttributeSessionPublicKey`].
#[pyfunction]
#[pyo3(name = "encrypt_attribute")]
pub fn py_encrypt_attribute(
    m: &PyAttribute,
    public_key: &PyAttributeSessionPublicKey,
) -> PyEncryptedAttribute {
    let mut rng = rand::rng();
    encrypt_attribute(
        &m.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    )
    .into()
}

/// Decrypt an [`PyEncryptedAttribute`] using a [`PyAttributeSessionSecretKey`].
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_attribute")]
pub fn py_decrypt_attribute(
    v: &PyEncryptedAttribute,
    secret_key: &PyAttributeSessionSecretKey,
) -> Option<PyAttribute> {
    decrypt_attribute(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).map(|x| x.into())
}

/// Decrypt an [`PyEncryptedAttribute`] using a [`PyAttributeSessionSecretKey`].
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_attribute")]
pub fn py_decrypt_attribute(
    v: &PyEncryptedAttribute,
    secret_key: &PyAttributeSessionSecretKey,
) -> PyAttribute {
    decrypt_attribute(&v.0, &AttributeSessionSecretKey::from(secret_key.0 .0)).into()
}

/// Pseudonymize an encrypted pseudonym from one domain/session to another.
#[pyfunction]
#[pyo3(name = "pseudonymize")]
pub fn py_pseudonymize(
    encrypted: &PyEncryptedPseudonym,
    pseudonymization_info: &PyPseudonymizationInfo,
) -> PyEncryptedPseudonym {
    pseudonymize(
        &encrypted.0,
        &PseudonymizationInfo::from(pseudonymization_info),
    )
    .into()
}

/// Rekey an encrypted pseudonym from one session to another.
#[pyfunction]
#[pyo3(name = "rekey_pseudonym")]
pub fn py_rekey_pseudonym(
    encrypted: &PyEncryptedPseudonym,
    rekey_info: &PyPseudonymRekeyFactor,
) -> PyEncryptedPseudonym {
    rekey_pseudonym(&encrypted.0, &rekey_info.0).into()
}

/// Rekey an encrypted attribute from one session to another.
#[pyfunction]
#[pyo3(name = "rekey_attribute")]
pub fn py_rekey_attribute(
    encrypted: &PyEncryptedAttribute,
    rekey_info: &PyAttributeRekeyInfo,
) -> PyEncryptedAttribute {
    rekey_attribute(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)).into()
}

/// Transcrypt an encrypted pseudonym from one domain/session to another.
#[pyfunction]
#[pyo3(name = "transcrypt_pseudonym")]
pub fn py_transcrypt_pseudonym(
    encrypted: &PyEncryptedPseudonym,
    transcryption_info: &PyTranscryptionInfo,
) -> PyEncryptedPseudonym {
    transcrypt_pseudonym(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}

/// Transcrypt an encrypted attribute from one session to another.
#[pyfunction]
#[pyo3(name = "transcrypt_attribute")]
pub fn py_transcrypt_attribute(
    encrypted: &PyEncryptedAttribute,
    transcryption_info: &PyTranscryptionInfo,
) -> PyEncryptedAttribute {
    transcrypt_attribute(&encrypted.0, &TranscryptionInfo::from(transcryption_info)).into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_encrypt_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_attribute, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_attribute, m)?)?;
    m.add_function(wrap_pyfunction!(py_pseudonymize, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_attribute, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_attribute, m)?)?;
    Ok(())
}
