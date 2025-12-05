//! Python bindings for batch transcryption operations.

use super::contexts::{PyAttributeRekeyInfo, PyPseudonymizationInfo, PyTranscryptionInfo};
use crate::core::py::data::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::core::transcryption::batch::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use pyo3::prelude::*;

/// Batch pseudonymization of a list of encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[pyfunction]
#[pyo3(name = "pseudonymize_batch")]
pub fn py_pseudonymize_batch(
    encrypted: Vec<PyEncryptedPseudonym>,
    pseudonymization_info: &PyPseudonymizationInfo,
) -> Vec<PyEncryptedPseudonym> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = PseudonymizationInfo::from(pseudonymization_info);
    pseudonymize_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(PyEncryptedPseudonym)
        .collect()
}

/// Batch rekeying of a list of encrypted attributes.
/// The order of the attributes is randomly shuffled to avoid linking them.
#[pyfunction]
#[pyo3(name = "rekey_batch")]
pub fn py_rekey_batch(
    encrypted: Vec<PyEncryptedAttribute>,
    rekey_info: &PyAttributeRekeyInfo,
) -> Vec<PyEncryptedAttribute> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let info = AttributeRekeyInfo::from(rekey_info);
    rekey_batch(&mut enc, &info, &mut rng)
        .into_vec()
        .into_iter()
        .map(PyEncryptedAttribute)
        .collect()
}

/// Batch transcryption of a list of encrypted data pairs.
/// Each pair contains a list of encrypted pseudonyms and a list of encrypted attributes.
/// The order of the pairs is randomly shuffled to avoid linking them.
///
/// # Errors
///
/// Raises a ValueError if the encrypted data do not all have the same structure.
#[pyfunction]
#[pyo3(name = "transcrypt_batch")]
pub fn py_transcrypt_batch(
    encrypted: Vec<(Vec<PyEncryptedPseudonym>, Vec<PyEncryptedAttribute>)>,
    transcryption_info: &PyTranscryptionInfo,
) -> PyResult<Vec<(Vec<PyEncryptedPseudonym>, Vec<PyEncryptedAttribute>)>> {
    let mut rng = rand::rng();
    let enc: Vec<_> = encrypted
        .into_iter()
        .map(|(ps, attrs)| {
            (
                ps.into_iter().map(|p| p.0).collect(),
                attrs.into_iter().map(|a| a.0).collect(),
            )
        })
        .collect();
    let info = TranscryptionInfo::from(transcryption_info);
    let result =
        transcrypt_batch(enc, &info, &mut rng).map_err(pyo3::exceptions::PyValueError::new_err)?;
    Ok(result
        .into_iter()
        .map(|(ps, attrs)| {
            (
                ps.into_iter().map(PyEncryptedPseudonym).collect(),
                attrs.into_iter().map(PyEncryptedAttribute).collect(),
            )
        })
        .collect())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_pseudonymize_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_batch, m)?)?;
    Ok(())
}
