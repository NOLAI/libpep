//! Python bindings for Record types.

use crate::client::{decrypt, encrypt};
#[cfg(feature = "long")]
use crate::data::py::long::{
    PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym, PyLongPseudonym,
};
use crate::data::py::simple::{
    PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym,
};
use crate::data::records::{EncryptedRecord, Record};
#[cfg(feature = "long")]
use crate::data::records::{LongEncryptedRecord, LongRecord};
use crate::keys::py::PySessionKeys;
use crate::keys::types::SessionKeys;
use pyo3::prelude::*;

/// A record containing multiple pseudonyms and attributes for a single entity.
#[pyclass(name = "Record")]
#[derive(Clone)]
pub struct PyRecord(pub(crate) Record);

#[pymethods]
impl PyRecord {
    /// Create a new Record with the given pseudonyms and attributes.
    #[new]
    pub fn new(pseudonyms: Vec<PyPseudonym>, attributes: Vec<PyAttribute>) -> Self {
        PyRecord(Record::new(
            pseudonyms.into_iter().map(|p| p.0).collect(),
            attributes.into_iter().map(|a| a.0).collect(),
        ))
    }

    /// Get the pseudonyms in this record.
    #[getter]
    pub fn pseudonyms(&self) -> Vec<PyPseudonym> {
        self.0.pseudonyms.iter().map(|p| PyPseudonym(*p)).collect()
    }

    /// Get the attributes in this record.
    #[getter]
    pub fn attributes(&self) -> Vec<PyAttribute> {
        self.0.attributes.iter().map(|a| PyAttribute(*a)).collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "Record(pseudonyms={}, attributes={})",
            self.0.pseudonyms.len(),
            self.0.attributes.len()
        )
    }
}

/// An encrypted record containing multiple encrypted pseudonyms and attributes.
#[pyclass(name = "EncryptedRecord")]
#[derive(Clone)]
pub struct PyEncryptedRecord(pub(crate) EncryptedRecord);

#[pymethods]
impl PyEncryptedRecord {
    /// Create a new EncryptedRecord with the given encrypted pseudonyms and attributes.
    #[new]
    pub fn new(
        pseudonyms: Vec<PyEncryptedPseudonym>,
        attributes: Vec<PyEncryptedAttribute>,
    ) -> Self {
        PyEncryptedRecord(EncryptedRecord::new(
            pseudonyms.into_iter().map(|p| p.0).collect(),
            attributes.into_iter().map(|a| a.0).collect(),
        ))
    }

    /// Get the encrypted pseudonyms in this record.
    #[getter]
    pub fn pseudonyms(&self) -> Vec<PyEncryptedPseudonym> {
        self.0
            .pseudonyms
            .iter()
            .map(|p| PyEncryptedPseudonym(*p))
            .collect()
    }

    /// Get the encrypted attributes in this record.
    #[getter]
    pub fn attributes(&self) -> Vec<PyEncryptedAttribute> {
        self.0
            .attributes
            .iter()
            .map(|a| PyEncryptedAttribute(*a))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "EncryptedRecord(pseudonyms={}, attributes={})",
            self.0.pseudonyms.len(),
            self.0.attributes.len()
        )
    }
}

/// Encrypt a Record using session keys.
#[pyfunction]
#[pyo3(name = "encrypt_record")]
pub fn py_encrypt_record(record: &PyRecord, session_keys: &PySessionKeys) -> PyEncryptedRecord {
    let mut rng = rand::rng();
    let keys: SessionKeys = session_keys.clone().into();
    PyEncryptedRecord(encrypt(&record.0, &keys, &mut rng))
}

/// Decrypt an EncryptedRecord using session keys.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_record")]
pub fn py_decrypt_record(
    encrypted: &PyEncryptedRecord,
    session_keys: &PySessionKeys,
) -> Option<PyRecord> {
    let keys: SessionKeys = session_keys.clone().into();
    decrypt(&encrypted.0, &keys).map(PyRecord)
}

/// Decrypt an EncryptedRecord using session keys.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_record")]
pub fn py_decrypt_record(encrypted: &PyEncryptedRecord, session_keys: &PySessionKeys) -> PyRecord {
    let keys: SessionKeys = session_keys.clone().into();
    PyRecord(decrypt(&encrypted.0, &keys))
}

// Long Record types (only when 'long' feature is enabled)

#[cfg(feature = "long")]
/// A long record containing multiple long pseudonyms and attributes for a single entity.
#[pyclass(name = "LongRecord")]
#[derive(Clone)]
pub struct PyLongRecord(pub(crate) LongRecord);

#[cfg(feature = "long")]
#[pymethods]
impl PyLongRecord {
    /// Create a new LongRecord with the given long pseudonyms and attributes.
    #[new]
    pub fn new(pseudonyms: Vec<PyLongPseudonym>, attributes: Vec<PyLongAttribute>) -> Self {
        PyLongRecord(LongRecord::new(
            pseudonyms.into_iter().map(|p| p.0).collect(),
            attributes.into_iter().map(|a| a.0).collect(),
        ))
    }

    /// Get the long pseudonyms in this record.
    #[getter]
    pub fn pseudonyms(&self) -> Vec<PyLongPseudonym> {
        self.0
            .pseudonyms
            .iter()
            .map(|p| PyLongPseudonym(p.clone()))
            .collect()
    }

    /// Get the long attributes in this record.
    #[getter]
    pub fn attributes(&self) -> Vec<PyLongAttribute> {
        self.0
            .attributes
            .iter()
            .map(|a| PyLongAttribute(a.clone()))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "LongRecord(pseudonyms={}, attributes={})",
            self.0.pseudonyms.len(),
            self.0.attributes.len()
        )
    }
}

#[cfg(feature = "long")]
/// An encrypted long record containing multiple encrypted long pseudonyms and attributes.
#[pyclass(name = "LongEncryptedRecord")]
#[derive(Clone)]
pub struct PyLongEncryptedRecord(pub(crate) LongEncryptedRecord);

#[cfg(feature = "long")]
#[pymethods]
impl PyLongEncryptedRecord {
    /// Create a new LongEncryptedRecord with the given encrypted long pseudonyms and attributes.
    #[new]
    pub fn new(
        pseudonyms: Vec<PyLongEncryptedPseudonym>,
        attributes: Vec<PyLongEncryptedAttribute>,
    ) -> Self {
        PyLongEncryptedRecord(LongEncryptedRecord::new(
            pseudonyms.into_iter().map(|p| p.0).collect(),
            attributes.into_iter().map(|a| a.0).collect(),
        ))
    }

    /// Get the encrypted long pseudonyms in this record.
    #[getter]
    pub fn pseudonyms(&self) -> Vec<PyLongEncryptedPseudonym> {
        self.0
            .pseudonyms
            .iter()
            .map(|p| PyLongEncryptedPseudonym(p.clone()))
            .collect()
    }

    /// Get the encrypted long attributes in this record.
    #[getter]
    pub fn attributes(&self) -> Vec<PyLongEncryptedAttribute> {
        self.0
            .attributes
            .iter()
            .map(|a| PyLongEncryptedAttribute(a.clone()))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "LongEncryptedRecord(pseudonyms={}, attributes={})",
            self.0.pseudonyms.len(),
            self.0.attributes.len()
        )
    }
}

#[cfg(feature = "long")]
/// Encrypt a LongRecord using session keys.
#[pyfunction]
#[pyo3(name = "encrypt_long_record")]
pub fn py_encrypt_long_record(
    record: &PyLongRecord,
    session_keys: &PySessionKeys,
) -> PyLongEncryptedRecord {
    let mut rng = rand::rng();
    let keys: SessionKeys = session_keys.clone().into();
    PyLongEncryptedRecord(encrypt(&record.0, &keys, &mut rng))
}

#[cfg(feature = "long")]
/// Decrypt a LongEncryptedRecord using session keys.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_long_record")]
pub fn py_decrypt_long_record(
    encrypted: &PyLongEncryptedRecord,
    session_keys: &PySessionKeys,
) -> Option<PyLongRecord> {
    let keys: SessionKeys = session_keys.clone().into();
    decrypt(&encrypted.0, &keys).map(PyLongRecord)
}

#[cfg(feature = "long")]
/// Decrypt a LongEncryptedRecord using session keys.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_long_record")]
pub fn py_decrypt_long_record(
    encrypted: &PyLongEncryptedRecord,
    session_keys: &PySessionKeys,
) -> PyLongRecord {
    let keys: SessionKeys = session_keys.clone().into();
    PyLongRecord(decrypt(&encrypted.0, &keys))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register Record types
    m.add_class::<PyRecord>()?;
    m.add_class::<PyEncryptedRecord>()?;

    // Register Long Record types (if long feature enabled)
    #[cfg(feature = "long")]
    {
        m.add_class::<PyLongRecord>()?;
        m.add_class::<PyLongEncryptedRecord>()?;
    }

    Ok(())
}
