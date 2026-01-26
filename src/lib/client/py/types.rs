//! Python bindings for client types.

#[cfg(feature = "offline")]
use crate::client::OfflineClient;
#[cfg(feature = "json")]
use crate::data::py::json::{PyEncryptedPEPJSONValue, PyPEPJSONValue};
#[cfg(feature = "long")]
use crate::data::py::long::{
    PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym, PyLongPseudonym,
};
use crate::data::py::records::{PyEncryptedRecord, PyRecord};
#[cfg(feature = "long")]
use crate::data::py::records::{PyLongEncryptedRecord, PyLongRecord};
use crate::data::py::simple::{
    PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym,
};
use crate::keys::py::PyGlobalPublicKeys;
use crate::keys::*;
use derive_more::{Deref, From, Into};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::IntoPyObjectExt;

/// An offline PEP client that can only encrypt (not decrypt).
#[cfg(feature = "offline")]
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "OfflineClient")]
pub struct PyOfflineClient(pub(crate) OfflineClient);

#[cfg(feature = "offline")]
#[pymethods]
impl PyOfflineClient {
    #[new]
    fn new(global_public_keys: &PyGlobalPublicKeys) -> Self {
        Self(OfflineClient::new(GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey(global_public_keys.pseudonym.0 .0),
            attribute: AttributeGlobalPublicKey(global_public_keys.attribute.0 .0),
        }))
    }

    /// Polymorphic encrypt that works with any encryptable type.
    #[pyo3(name = "encrypt")]
    fn py_encrypt(&self, message: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
        let py = message.py();
        let mut rng = rand::rng();

        // Try Pseudonym
        if let Ok(p) = message.extract::<PyPseudonym>() {
            let result = self.0.encrypt(&p.0, &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        // Try Attribute
        if let Ok(a) = message.extract::<PyAttribute>() {
            let result = self.0.encrypt(&a.0, &mut rng);
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }

        // Try LongPseudonym
        #[cfg(feature = "long")]
        if let Ok(lp) = message.extract::<PyLongPseudonym>() {
            let result = self.0.encrypt(&lp.0, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }

        // Try LongAttribute
        #[cfg(feature = "long")]
        if let Ok(la) = message.extract::<PyLongAttribute>() {
            let result = self.0.encrypt(&la.0, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "encrypt() requires Pseudonym, Attribute, LongPseudonym, or LongAttribute",
        ))
    }

    /// Polymorphic batch encryption.
    #[cfg(feature = "batch")]
    #[pyo3(name = "encrypt_batch")]
    fn py_encrypt_batch(&self, messages: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
        let py = messages.py();
        let mut rng = rand::rng();

        // Try Vec<Pseudonym>
        if let Ok(ps) = messages.extract::<Vec<PyPseudonym>>() {
            let msgs: Vec<_> = ps.into_iter().map(|p| p.0).collect();
            let result = self
                .0
                .encrypt_batch(&msgs, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyEncryptedPseudonym> =
                result.into_iter().map(PyEncryptedPseudonym).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<Attribute>
        if let Ok(attrs) = messages.extract::<Vec<PyAttribute>>() {
            let msgs: Vec<_> = attrs.into_iter().map(|a| a.0).collect();
            let result = self
                .0
                .encrypt_batch(&msgs, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyEncryptedAttribute> =
                result.into_iter().map(PyEncryptedAttribute).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongPseudonym>
        #[cfg(feature = "long")]
        if let Ok(lps) = messages.extract::<Vec<PyLongPseudonym>>() {
            let msgs: Vec<_> = lps.into_iter().map(|p| p.0).collect();
            let result = self
                .0
                .encrypt_batch(&msgs, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongEncryptedPseudonym> =
                result.into_iter().map(PyLongEncryptedPseudonym).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongAttribute>
        #[cfg(feature = "long")]
        if let Ok(las) = messages.extract::<Vec<PyLongAttribute>>() {
            let msgs: Vec<_> = las.into_iter().map(|a| a.0).collect();
            let result = self
                .0
                .encrypt_batch(&msgs, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongEncryptedAttribute> =
                result.into_iter().map(PyLongEncryptedAttribute).collect();
            return py_result.into_py_any(py);
        }

        Err(PyTypeError::new_err(
            "encrypt_batch() requires Vec[Pseudonym], Vec[Attribute], Vec[LongPseudonym], or Vec[LongAttribute]",
        ))
    }

    /// Encrypt a Record using global public keys (offline mode).
    #[pyo3(name = "encrypt_record")]
    fn py_encrypt_record(&self, record: &PyRecord) -> PyResult<PyEncryptedRecord> {
        use crate::data::traits::Encryptable;
        let mut rng = rand::rng();
        let result = record
            .0
            .encrypt_global(&self.0.global_public_keys, &mut rng);
        Ok(PyEncryptedRecord(result))
    }

    /// Encrypt a LongRecord using global public keys (offline mode).
    #[cfg(feature = "long")]
    #[pyo3(name = "encrypt_long_record")]
    fn py_encrypt_long_record(&self, record: &PyLongRecord) -> PyResult<PyLongEncryptedRecord> {
        use crate::data::traits::Encryptable;
        let mut rng = rand::rng();
        let result = record
            .0
            .encrypt_global(&self.0.global_public_keys, &mut rng);
        Ok(PyLongEncryptedRecord(result))
    }

    /// Encrypt a PEPJSONValue using global public keys (offline mode).
    #[cfg(feature = "json")]
    #[pyo3(name = "encrypt_json")]
    fn py_encrypt_json(&self, value: &PyPEPJSONValue) -> PyResult<PyEncryptedPEPJSONValue> {
        use crate::data::traits::Encryptable;
        let mut rng = rand::rng();
        let result = value.0.encrypt_global(&self.0.global_public_keys, &mut rng);
        Ok(PyEncryptedPEPJSONValue(result))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(feature = "offline")]
    m.add_class::<PyOfflineClient>()?;
    Ok(())
}
