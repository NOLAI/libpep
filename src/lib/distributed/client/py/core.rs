use super::super::client::PEPClient;
use super::keys::{
    PyAttributeSessionKeyShare, PyPseudonymSessionKeyShare, PySessionKeyShares, PySessionKeys,
    PySessionPublicKeys, PySessionSecretKeys,
};
use crate::arithmetic::py::{PyGroupElement, PyScalarNonZero};
use crate::core::keys::*;
#[cfg(feature = "long")]
use crate::core::long::py::data::{
    PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym, PyLongPseudonym,
};
use crate::core::py::data::{PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym};
use crate::core::py::keys::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey,
};
use crate::distributed::server::keys::*;
use crate::distributed::server::py::setup::PyBlindedGlobalKeys;
use crate::distributed::server::setup::BlindedGlobalKeys;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

/// A PEP client.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "PEPClient")]
pub struct PyPEPClient(PEPClient);

#[pymethods]
impl PyPEPClient {
    #[new]
    fn new(
        blinded_global_keys: &PyBlindedGlobalKeys,
        session_key_shares: Vec<PySessionKeyShares>,
    ) -> Self {
        let shares: Vec<SessionKeyShares> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShares {
                pseudonym: PseudonymSessionKeyShare(x.pseudonym.0 .0),
                attribute: AttributeSessionKeyShare(x.attribute.0 .0),
            })
            .collect();
        let blinded_keys = BlindedGlobalKeys {
            pseudonym: blinded_global_keys.pseudonym.0,
            attribute: blinded_global_keys.attribute.0,
        };
        Self(PEPClient::new(blinded_keys, &shares))
    }

    #[staticmethod]
    #[pyo3(name = "restore")]
    fn py_restore(keys: &PySessionKeys) -> Self {
        let keys = SessionKeys {
            pseudonym: PseudonymSessionKeys {
                public: PseudonymSessionPublicKey(keys.public.pseudonym.0 .0),
                secret: PseudonymSessionSecretKey(keys.secret.pseudonym.0 .0),
            },
            attribute: AttributeSessionKeys {
                public: AttributeSessionPublicKey(keys.public.attribute.0 .0),
                secret: AttributeSessionSecretKey(keys.secret.attribute.0 .0),
            },
        };
        Self(PEPClient::restore(keys))
    }

    #[pyo3(name = "dump")]
    fn py_dump(&self) -> PySessionKeys {
        let keys = self.0.dump();
        PySessionKeys {
            public: PySessionPublicKeys {
                pseudonym: PyPseudonymSessionPublicKey::from(PyGroupElement::from(
                    keys.pseudonym.public.0,
                )),
                attribute: PyAttributeSessionPublicKey::from(PyGroupElement::from(
                    keys.attribute.public.0,
                )),
            },
            secret: PySessionSecretKeys {
                pseudonym: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(
                    keys.pseudonym.secret.0,
                )),
                attribute: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(
                    keys.attribute.secret.0,
                )),
            },
        }
    }

    #[pyo3(name = "update_pseudonym_session_secret_key")]
    fn py_update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: PyPseudonymSessionKeyShare,
        new_key_share: PyPseudonymSessionKeyShare,
    ) {
        self.0
            .update_pseudonym_session_secret_key(old_key_share.0, new_key_share.0);
    }

    #[pyo3(name = "update_attribute_session_secret_key")]
    fn py_update_attribute_session_secret_key(
        &mut self,
        old_key_share: PyAttributeSessionKeyShare,
        new_key_share: PyAttributeSessionKeyShare,
    ) {
        self.0
            .update_attribute_session_secret_key(old_key_share.0, new_key_share.0);
    }

    #[pyo3(name = "update_session_secret_keys")]
    fn py_update_session_secret_keys(
        &mut self,
        old_key_shares: PySessionKeyShares,
        new_key_shares: PySessionKeyShares,
    ) {
        let old_shares = SessionKeyShares {
            pseudonym: PseudonymSessionKeyShare(old_key_shares.pseudonym.0 .0),
            attribute: AttributeSessionKeyShare(old_key_shares.attribute.0 .0),
        };
        let new_shares = SessionKeyShares {
            pseudonym: PseudonymSessionKeyShare(new_key_shares.pseudonym.0 .0),
            attribute: AttributeSessionKeyShare(new_key_shares.attribute.0 .0),
        };
        self.0.update_session_secret_keys(old_shares, new_shares);
    }

    #[pyo3(name = "decrypt_pseudonym")]
    #[cfg(feature = "elgamal3")]
    fn py_decrypt_pseudonym(&self, encrypted: &PyEncryptedPseudonym) -> Option<PyPseudonym> {
        self.decrypt_pseudonym(&encrypted.0).map(PyPseudonym::from)
    }

    #[pyo3(name = "decrypt_pseudonym")]
    #[cfg(not(feature = "elgamal3"))]
    fn py_decrypt_pseudonym(&self, encrypted: &PyEncryptedPseudonym) -> PyPseudonym {
        PyPseudonym::from(self.decrypt_pseudonym(&encrypted.0))
    }

    #[pyo3(name = "decrypt_data")]
    #[cfg(feature = "elgamal3")]
    fn py_decrypt_data(&self, encrypted: &PyEncryptedAttribute) -> Option<PyAttribute> {
        self.decrypt_attribute(&encrypted.0).map(PyAttribute::from)
    }

    #[pyo3(name = "decrypt_data")]
    #[cfg(not(feature = "elgamal3"))]
    fn py_decrypt_data(&self, encrypted: &PyEncryptedAttribute) -> PyAttribute {
        PyAttribute::from(self.decrypt_attribute(&encrypted.0))
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

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[pyo3(name = "decrypt_long_pseudonym")]
    fn py_decrypt_long_pseudonym(
        &self,
        encrypted: &PyLongEncryptedPseudonym,
    ) -> Option<PyLongPseudonym> {
        self.decrypt_long_pseudonym(&encrypted.0)
            .map(PyLongPseudonym::from)
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[pyo3(name = "decrypt_long_pseudonym")]
    fn py_decrypt_long_pseudonym(&self, encrypted: &PyLongEncryptedPseudonym) -> PyLongPseudonym {
        PyLongPseudonym::from(self.decrypt_long_pseudonym(&encrypted.0))
    }

    #[cfg(feature = "long")]
    #[pyo3(name = "encrypt_long_data")]
    fn py_encrypt_long_data(&self, message: &PyLongAttribute) -> PyLongEncryptedAttribute {
        let mut rng = rand::rng();
        PyLongEncryptedAttribute::from(self.encrypt_long_attribute(&message.0, &mut rng))
    }

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[pyo3(name = "decrypt_long_data")]
    fn py_decrypt_long_data(
        &self,
        encrypted: &PyLongEncryptedAttribute,
    ) -> Option<PyLongAttribute> {
        self.decrypt_long_attribute(&encrypted.0)
            .map(PyLongAttribute::from)
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[pyo3(name = "decrypt_long_data")]
    fn py_decrypt_long_data(&self, encrypted: &PyLongEncryptedAttribute) -> PyLongAttribute {
        PyLongAttribute::from(self.decrypt_long_attribute(&encrypted.0))
    }

    /// Encrypt a PEPJSONValue into an EncryptedPEPJSONValue.
    ///
    /// Args:
    ///     pep_value: The unencrypted PEPJSONValue to encrypt
    ///
    /// Returns:
    ///     An EncryptedPEPJSONValue
    #[cfg(feature = "json")]
    #[pyo3(name = "encrypt_json")]
    fn encrypt_json(
        &self,
        pep_value: &crate::core::json::py::PyPEPJSONValue,
    ) -> crate::core::json::py::PyEncryptedPEPJSONValue {
        let mut rng = rand::rng();
        let encrypted = self.0.encrypt_json_value(&pep_value.0, &mut rng);
        crate::core::json::py::PyEncryptedPEPJSONValue(encrypted)
    }

    /// Decrypt an EncryptedPEPJSONValue back to a regular Python object.
    ///
    /// Args:
    ///     encrypted: The EncryptedPEPJSONValue to decrypt
    ///
    /// Returns:
    ///     A Python object (dict, list, str, int, float, bool, or None)
    #[cfg(feature = "json")]
    #[pyo3(name = "decrypt_json")]
    fn decrypt_json(
        &self,
        encrypted: &crate::core::json::py::PyEncryptedPEPJSONValue,
    ) -> PyResult<crate::core::json::py::PyPEPJSONValue> {
        let decrypted = self.0.decrypt_json_value(&encrypted.0).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decryption failed: {}", e))
        })?;

        Ok(crate::core::json::py::PyPEPJSONValue(decrypted))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPEPClient>()?;
    Ok(())
}
