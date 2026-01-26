//! Python bindings for distributed client.

use crate::client::distributed::make_session_keys_distributed;
use crate::client::Client;
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
use crate::keys::distribution::{
    AttributeSessionKeyShare, BlindedGlobalKeys, PseudonymSessionKeyShare, SessionKeyShares,
};
use crate::keys::py::types::{PyAttributeSessionKeys, PyPseudonymSessionKeys, PySessionKeys};
use crate::keys::py::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyBlindedGlobalKeys,
    PyPseudonymSessionPublicKey, PyPseudonymSessionSecretKey,
};
use crate::keys::py::{PySessionKeyShares, PySessionPublicKeys, PySessionSecretKeys};
use crate::keys::*;
use derive_more::{Deref, From, Into};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::IntoPyObjectExt;

/// A PEP client.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "Client")]
pub struct PyClient(Client);

#[pymethods]
impl PyClient {
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
        let keys = make_session_keys_distributed(blinded_keys, &shares);
        Self(Client::new(keys))
    }

    #[staticmethod]
    #[pyo3(name = "restore")]
    fn py_restore(keys: &PySessionKeys) -> Self {
        Self(Client::restore(SessionKeys::from(keys.clone())))
    }

    #[pyo3(name = "session_keys")]
    fn py_session_keys(&self) -> PySessionKeys {
        let keys = self.0.dump();
        PySessionKeys {
            pseudonym: PyPseudonymSessionKeys {
                public: PyPseudonymSessionPublicKey(keys.pseudonym.public.0.into()),
                secret: PyPseudonymSessionSecretKey(keys.pseudonym.secret.0.into()),
            },
            attribute: PyAttributeSessionKeys {
                public: PyAttributeSessionPublicKey(keys.attribute.public.0.into()),
                secret: PyAttributeSessionSecretKey(keys.attribute.secret.0.into()),
            },
        }
    }

    #[pyo3(name = "dump")]
    fn py_dump(&self) -> PySessionKeys {
        let keys = self.0.dump();
        PySessionKeys {
            pseudonym: PyPseudonymSessionKeys {
                public: PyPseudonymSessionPublicKey(keys.pseudonym.public.0.into()),
                secret: PyPseudonymSessionSecretKey(keys.pseudonym.secret.0.into()),
            },
            attribute: PyAttributeSessionKeys {
                public: PyAttributeSessionPublicKey(keys.attribute.public.0.into()),
                secret: PyAttributeSessionSecretKey(keys.attribute.secret.0.into()),
            },
        }
    }

    #[pyo3(name = "session_public_keys")]
    fn py_session_public_keys(&self) -> PySessionPublicKeys {
        let keys = self.0.dump();
        PySessionPublicKeys {
            pseudonym: PyPseudonymSessionPublicKey(keys.pseudonym.public.0.into()),
            attribute: PyAttributeSessionPublicKey(keys.attribute.public.0.into()),
        }
    }

    #[pyo3(name = "session_secret_keys")]
    fn py_session_secret_keys(&self) -> PySessionSecretKeys {
        let keys = self.0.dump();
        PySessionSecretKeys {
            pseudonym: PyPseudonymSessionSecretKey(keys.pseudonym.secret.0.into()),
            attribute: PyAttributeSessionSecretKey(keys.attribute.secret.0.into()),
        }
    }

    /// Polymorphic encrypt that works with any encryptable type.
    /// Automatically selects the correct key based on the message type.
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

        // Try Record - uses SessionKeys directly
        if let Ok(r) = message.extract::<PyRecord>() {
            use crate::data::traits::Encryptable;
            let result = r.0.encrypt(&self.0.keys, &mut rng);
            return Ok(Py::new(py, PyEncryptedRecord(result))?.into_any());
        }

        // Try LongRecord - uses SessionKeys directly
        #[cfg(feature = "long")]
        if let Ok(lr) = message.extract::<PyLongRecord>() {
            use crate::data::traits::Encryptable;
            let result = lr.0.encrypt(&self.0.keys, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedRecord(result))?.into_any());
        }

        // Try PEPJSONValue - uses SessionKeys directly
        #[cfg(feature = "json")]
        if let Ok(j) = message.extract::<PyPEPJSONValue>() {
            use crate::data::traits::Encryptable;
            let result = j.0.encrypt(&self.0.keys, &mut rng);
            return Ok(Py::new(py, PyEncryptedPEPJSONValue(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "encrypt() requires Pseudonym, Attribute, LongPseudonym, LongAttribute, Record, LongRecord, or PEPJSONValue",
        ))
    }

    /// Polymorphic decrypt that works with any encrypted type.
    /// Automatically selects the correct key based on the encrypted type.
    #[cfg(feature = "elgamal3")]
    #[pyo3(name = "decrypt")]
    fn py_decrypt(&self, encrypted: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();

        // Try EncryptedPseudonym
        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self
                .0
                .decrypt(&ep.0)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))?;
            return Ok(Py::new(py, PyPseudonym(result))?.into_any());
        }

        // Try EncryptedAttribute
        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            let result = self
                .0
                .decrypt(&ea.0)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))?;
            return Ok(Py::new(py, PyAttribute(result))?.into_any());
        }

        // Try LongEncryptedPseudonym
        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self
                .0
                .decrypt(&lep.0)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))?;
            return Ok(Py::new(py, PyLongPseudonym(result))?.into_any());
        }

        // Try LongEncryptedAttribute
        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            let result = self
                .0
                .decrypt(&lea.0)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))?;
            return Ok(Py::new(py, PyLongAttribute(result))?.into_any());
        }

        // Try EncryptedRecord - uses SessionKeys directly
        if let Ok(er) = encrypted.extract::<PyEncryptedRecord>() {
            use crate::data::traits::Encrypted;
            let result =
                er.0.decrypt(&self.0.keys)
                    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))?;
            return Ok(Py::new(py, PyRecord(result))?.into_any());
        }

        // Try LongEncryptedRecord - uses SessionKeys directly
        #[cfg(feature = "long")]
        if let Ok(ler) = encrypted.extract::<PyLongEncryptedRecord>() {
            use crate::data::traits::Encrypted;
            let result = ler
                .0
                .decrypt(&self.0.keys)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))?;
            return Ok(Py::new(py, PyLongRecord(result))?.into_any());
        }

        // Try EncryptedPEPJSONValue - uses SessionKeys directly
        #[cfg(feature = "json")]
        if let Ok(ej) = encrypted.extract::<PyEncryptedPEPJSONValue>() {
            use crate::data::traits::Encrypted;
            let result =
                ej.0.decrypt(&self.0.keys)
                    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Decryption failed"))?;
            return Ok(Py::new(py, PyPEPJSONValue(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "decrypt() requires EncryptedPseudonym, EncryptedAttribute, LongEncryptedPseudonym, LongEncryptedAttribute, EncryptedRecord, LongEncryptedRecord, or EncryptedPEPJSONValue",
        ))
    }

    /// Polymorphic decrypt that works with any encrypted type.
    /// Automatically selects the correct key based on the encrypted type.
    #[cfg(not(feature = "elgamal3"))]
    #[pyo3(name = "decrypt")]
    fn py_decrypt(&self, encrypted: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();

        // Try EncryptedPseudonym
        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.decrypt(&ep.0);
            return Ok(Py::new(py, PyPseudonym(result))?.into_any());
        }

        // Try EncryptedAttribute
        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            let result = self.0.decrypt(&ea.0);
            return Ok(Py::new(py, PyAttribute(result))?.into_any());
        }

        // Try LongEncryptedPseudonym
        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self.0.decrypt(&lep.0);
            return Ok(Py::new(py, PyLongPseudonym(result))?.into_any());
        }

        // Try LongEncryptedAttribute
        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            let result = self.0.decrypt(&lea.0);
            return Ok(Py::new(py, PyLongAttribute(result))?.into_any());
        }

        // Try EncryptedRecord - uses SessionKeys directly
        if let Ok(er) = encrypted.extract::<PyEncryptedRecord>() {
            use crate::data::traits::Encrypted;
            let result = er.0.decrypt(&self.0.keys);
            return Ok(Py::new(py, PyRecord(result))?.into_any());
        }

        // Try LongEncryptedRecord - uses SessionKeys directly
        #[cfg(feature = "long")]
        if let Ok(ler) = encrypted.extract::<PyLongEncryptedRecord>() {
            use crate::data::traits::Encrypted;
            let result = ler.0.decrypt(&self.0.keys);
            return Ok(Py::new(py, PyLongRecord(result))?.into_any());
        }

        // Try EncryptedPEPJSONValue - uses SessionKeys directly
        #[cfg(feature = "json")]
        if let Ok(ej) = encrypted.extract::<PyEncryptedPEPJSONValue>() {
            use crate::data::traits::Encrypted;
            let result = ej.0.decrypt(&self.0.keys);
            return Ok(Py::new(py, PyPEPJSONValue(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "decrypt() requires EncryptedPseudonym, EncryptedAttribute, LongEncryptedPseudonym, LongEncryptedAttribute, EncryptedRecord, LongEncryptedRecord, or EncryptedPEPJSONValue",
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

    /// Polymorphic batch decryption.
    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    #[pyo3(name = "decrypt_batch")]
    fn py_decrypt_batch(&self, encrypted: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();

        // Try Vec<EncryptedPseudonym>
        if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
            let enc: Vec<_> = eps.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyPseudonym> = result.into_iter().map(PyPseudonym).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<EncryptedAttribute>
        if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
            let enc: Vec<_> = eas.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyAttribute> = result.into_iter().map(PyAttribute).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongEncryptedPseudonym>
        #[cfg(feature = "long")]
        if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
            let enc: Vec<_> = leps.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongPseudonym> = result.into_iter().map(PyLongPseudonym).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongEncryptedAttribute>
        #[cfg(feature = "long")]
        if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
            let enc: Vec<_> = leas.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongAttribute> = result.into_iter().map(PyLongAttribute).collect();
            return py_result.into_py_any(py);
        }

        Err(PyTypeError::new_err(
            "decrypt_batch() requires Vec[EncryptedPseudonym], Vec[EncryptedAttribute], Vec[LongEncryptedPseudonym], or Vec[LongEncryptedAttribute]",
        ))
    }

    /// Polymorphic batch decryption.
    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    #[pyo3(name = "decrypt_batch")]
    fn py_decrypt_batch(&self, encrypted: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();

        // Try Vec<EncryptedPseudonym>
        if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
            let enc: Vec<_> = eps.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyPseudonym> = result.into_iter().map(PyPseudonym).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<EncryptedAttribute>
        if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
            let enc: Vec<_> = eas.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyAttribute> = result.into_iter().map(PyAttribute).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongEncryptedPseudonym>
        #[cfg(feature = "long")]
        if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
            let enc: Vec<_> = leps.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongPseudonym> = result.into_iter().map(PyLongPseudonym).collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongEncryptedAttribute>
        #[cfg(feature = "long")]
        if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
            let enc: Vec<_> = leas.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .decrypt_batch(&enc)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongAttribute> = result.into_iter().map(PyLongAttribute).collect();
            return py_result.into_py_any(py);
        }

        Err(PyTypeError::new_err(
            "decrypt_batch() requires Vec[EncryptedPseudonym], Vec[EncryptedAttribute], Vec[LongEncryptedPseudonym], or Vec[LongEncryptedAttribute]",
        ))
    }

    /// Update session secret keys from one session to another.
    #[pyo3(name = "update_session_secret_keys")]
    fn py_update_session_secret_keys(
        &mut self,
        old_key_shares: &PySessionKeyShares,
        new_key_shares: &PySessionKeyShares,
    ) {
        use crate::client::distributed::Distributed;
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
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyClient>()?;
    Ok(())
}
