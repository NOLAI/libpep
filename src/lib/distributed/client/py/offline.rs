use super::super::offline::OfflinePEPClient;
use crate::core::keys::*;
#[cfg(feature = "long")]
use crate::core::long::py::data::{
    PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym, PyLongPseudonym,
};
use crate::core::py::data::{PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym};
use crate::core::py::keys::PyGlobalPublicKeys;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

/// An offline PEP client for encryption only.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "OfflinePEPClient")]
pub struct PyOfflinePEPClient(OfflinePEPClient);

#[pymethods]
impl PyOfflinePEPClient {
    #[new]
    fn new(global_keys: &PyGlobalPublicKeys) -> Self {
        let global_keys = GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey(global_keys.pseudonym.0 .0),
            attribute: AttributeGlobalPublicKey(global_keys.attribute.0 .0),
        };
        Self(OfflinePEPClient::new(global_keys))
    }

    #[pyo3(name = "encrypt_data")]
    fn py_encrypt_data(&self, message: &PyAttribute) -> PyEncryptedAttribute {
        let mut rng = rand::rng();
        PyEncryptedAttribute::from(self.encrypt_attribute(&message.0, &mut rng))
    }

    #[pyo3(name = "encrypt_pseudonym")]
    fn py_encrypt_pseudonym(&self, message: &PyPseudonym) -> PyEncryptedPseudonym {
        let mut rng = rand::rng();
        PyEncryptedPseudonym(self.encrypt_pseudonym(&message.0, &mut rng))
    }

    #[cfg(feature = "long")]
    #[pyo3(name = "encrypt_long_pseudonym")]
    fn py_encrypt_long_pseudonym(&self, message: &PyLongPseudonym) -> PyLongEncryptedPseudonym {
        let mut rng = rand::rng();
        PyLongEncryptedPseudonym::from(self.encrypt_long_pseudonym(&message.0, &mut rng))
    }

    #[cfg(feature = "long")]
    #[pyo3(name = "encrypt_long_data")]
    fn py_encrypt_long_data(&self, message: &PyLongAttribute) -> PyLongEncryptedAttribute {
        let mut rng = rand::rng();
        PyLongEncryptedAttribute::from(self.encrypt_long_attribute(&message.0, &mut rng))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyOfflinePEPClient>()?;
    Ok(())
}
