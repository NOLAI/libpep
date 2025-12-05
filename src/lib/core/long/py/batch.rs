//! Python bindings for batch operations on long (multi-block) data types.

use super::data::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::core::long::batch::{
    pseudonymize_long_batch, rekey_long_attribute_batch, rekey_long_pseudonym_batch,
    transcrypt_long_batch, LongEncryptedData,
};
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::core::transcryption::py::contexts::{
    PyAttributeRekeyInfo, PyPseudonymRekeyFactor, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use pyo3::prelude::*;

/// Batch pseudonymization of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[pyfunction]
#[pyo3(name = "pseudonymize_long_batch")]
pub fn py_pseudonymize_long_batch(
    encrypted: Vec<PyLongEncryptedPseudonym>,
    pseudonymization_info: &PyPseudonymizationInfo,
) -> Vec<PyLongEncryptedPseudonym> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = PseudonymizationInfo::from(pseudonymization_info);
    pseudonymize_long_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(PyLongEncryptedPseudonym)
        .collect()
}

/// Batch rekeying of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[pyfunction]
#[pyo3(name = "rekey_long_pseudonym_batch")]
pub fn py_rekey_long_pseudonym_batch(
    encrypted: Vec<PyLongEncryptedPseudonym>,
    rekey_info: &PyPseudonymRekeyFactor,
) -> Vec<PyLongEncryptedPseudonym> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = PseudonymRekeyInfo::from(rekey_info.0);
    rekey_long_pseudonym_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(PyLongEncryptedPseudonym)
        .collect()
}

/// Batch rekeying of long encrypted attributes.
/// The order of the attributes is randomly shuffled to avoid linking them.
#[pyfunction]
#[pyo3(name = "rekey_long_attribute_batch")]
pub fn py_rekey_long_attribute_batch(
    encrypted: Vec<PyLongEncryptedAttribute>,
    rekey_info: &PyAttributeRekeyInfo,
) -> Vec<PyLongEncryptedAttribute> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = AttributeRekeyInfo::from(rekey_info);
    rekey_long_attribute_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(PyLongEncryptedAttribute)
        .collect()
}

/// Batch transcryption of long encrypted data.
/// Each item contains a list of long encrypted pseudonyms and a list of long encrypted attributes.
/// The order of the items is randomly shuffled to avoid linking them.
///
/// # Errors
///
/// Raises a ValueError if the encrypted data do not all have the same structure.
#[pyfunction]
#[pyo3(name = "transcrypt_long_batch")]
pub fn py_transcrypt_long_batch(
    encrypted: Vec<(Vec<PyLongEncryptedPseudonym>, Vec<PyLongEncryptedAttribute>)>,
    transcryption_info: &PyTranscryptionInfo,
) -> PyResult<Vec<(Vec<PyLongEncryptedPseudonym>, Vec<PyLongEncryptedAttribute>)>> {
    let mut rng = rand::rng();
    let enc: Vec<LongEncryptedData> = encrypted
        .into_iter()
        .map(|(ps, attrs)| {
            (
                ps.into_iter().map(|p| p.0).collect(),
                attrs.into_iter().map(|a| a.0).collect(),
            )
        })
        .collect();
    let info = TranscryptionInfo::from(transcryption_info);
    let result = transcrypt_long_batch(enc, &info, &mut rng)
        .map_err(pyo3::exceptions::PyValueError::new_err)?;
    Ok(result
        .into_iter()
        .map(|(ps, attrs)| {
            (
                ps.into_iter().map(PyLongEncryptedPseudonym).collect(),
                attrs.into_iter().map(PyLongEncryptedAttribute).collect(),
            )
        })
        .collect())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_pseudonymize_long_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_long_pseudonym_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_long_attribute_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_long_batch, m)?)?;
    Ok(())
}
