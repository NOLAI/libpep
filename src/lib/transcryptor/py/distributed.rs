//! Python bindings for distributed transcryptor.

#[cfg(all(feature = "json", feature = "elgamal3"))]
use crate::data::py::json::PyEncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::py::long::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
#[cfg(feature = "elgamal3")]
use crate::data::py::records::PyEncryptedRecord;
#[cfg(all(feature = "long", feature = "elgamal3"))]
use crate::data::py::records::PyLongEncryptedRecord;
use crate::data::py::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::py::contexts::{
    PyAttributeRekeyInfo, PyEncryptionContext, PyPseudonymRekeyFactor, PyPseudonymizationDomain,
    PyPseudonymizationInfo, PyTranscryptionInfo,
};
use crate::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymizationInfo, PseudonymizationSecret,
    TranscryptionInfo,
};
use crate::keys::distribution::BlindingFactor;
use crate::keys::py::distribution::PyBlindingFactor;
use crate::keys::py::{PyAttributeSessionKeyShare, PyPseudonymSessionKeyShare, PySessionKeyShares};
use crate::transcryptor::DistributedTranscryptor;
use derive_more::{Deref, From, Into};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

/// A distributed PEP transcryptor system with blinding factor support.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "DistributedTranscryptor", from_py_object)]
pub struct PyDistributedTranscryptor(pub(crate) DistributedTranscryptor);

#[pymethods]
impl PyDistributedTranscryptor {
    #[new]
    fn new(
        pseudonymisation_secret: &str,
        rekeying_secret: &str,
        blinding_factor: &PyBlindingFactor,
    ) -> Self {
        Self(DistributedTranscryptor::new(
            PseudonymizationSecret::from(pseudonymisation_secret.as_bytes().to_vec()),
            EncryptionSecret::from(rekeying_secret.as_bytes().to_vec()),
            BlindingFactor(blinding_factor.0 .0),
        ))
    }

    #[pyo3(name = "pseudonym_session_key_share")]
    fn py_pseudonym_session_key_share(
        &self,
        session: &PyEncryptionContext,
    ) -> PyPseudonymSessionKeyShare {
        PyPseudonymSessionKeyShare(self.pseudonym_session_key_share(&session.0))
    }

    #[pyo3(name = "attribute_session_key_share")]
    fn py_attribute_session_key_share(
        &self,
        session: &PyEncryptionContext,
    ) -> PyAttributeSessionKeyShare {
        PyAttributeSessionKeyShare(self.attribute_session_key_share(&session.0))
    }

    #[pyo3(name = "session_key_shares")]
    fn py_session_key_shares(&self, session: &PyEncryptionContext) -> PySessionKeyShares {
        let shares = self.session_key_shares(&session.0);
        PySessionKeyShares {
            pseudonym: PyPseudonymSessionKeyShare(shares.pseudonym),
            attribute: PyAttributeSessionKeyShare(shares.attribute),
        }
    }

    #[pyo3(name = "attribute_rekey_info")]
    fn py_attribute_rekey_info(
        &self,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> PyAttributeRekeyInfo {
        PyAttributeRekeyInfo::from(self.attribute_rekey_info(&session_from.0, &session_to.0))
    }

    #[pyo3(name = "pseudonym_rekey_info")]
    fn py_pseudonym_rekey_info(
        &self,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> PyPseudonymRekeyFactor {
        PyPseudonymRekeyFactor(self.pseudonym_rekey_info(&session_from.0, &session_to.0))
    }

    #[pyo3(name = "pseudonymization_info")]
    fn py_pseudonymization_info(
        &self,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> PyPseudonymizationInfo {
        PyPseudonymizationInfo::from(self.pseudonymization_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    #[pyo3(name = "transcryption_info")]
    fn py_transcryption_info(
        &self,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> PyTranscryptionInfo {
        PyTranscryptionInfo::from(self.transcryption_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    /// Polymorphic rekey that works with any rekeyable type.
    #[pyo3(name = "rekey")]
    fn py_rekey(&self, encrypted: &Bound<PyAny>, rekey_info: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();

        // Try EncryptedAttribute with AttributeRekeyInfo
        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
                let result = self.0.rekey(&ea.0, &AttributeRekeyInfo::from(&info));
                return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
            }
        }

        // Try LongEncryptedAttribute with AttributeRekeyInfo
        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
                let result = self.0.rekey(&lea.0, &AttributeRekeyInfo::from(&info));
                return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
            }
        }

        // Try EncryptedPseudonym with PseudonymRekeyFactor
        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
                let result = self.0.rekey(&ep.0, &info.0);
                return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
            }
        }

        // Try LongEncryptedPseudonym with PseudonymRekeyFactor
        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
                let result = self.0.rekey(&lep.0, &info.0);
                return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
            }
        }

        Err(PyTypeError::new_err(
            "rekey() requires (EncryptedAttribute | LongEncryptedAttribute, AttributeRekeyInfo) or (EncryptedPseudonym | LongEncryptedPseudonym, PseudonymRekeyFactor)",
        ))
    }

    /// Polymorphic pseudonymize that works with any pseudonymizable type.
    #[cfg(feature = "elgamal3")]
    #[pyo3(name = "pseudonymize")]
    fn py_pseudonymize(
        &self,
        encrypted: &Bound<PyAny>,
        pseudonymization_info: &PyPseudonymizationInfo,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(pseudonymization_info);

        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.pseudonymize(&ep.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self.0.pseudonymize(&lep.0, &info, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "pseudonymize() requires EncryptedPseudonym or LongEncryptedPseudonym",
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[pyo3(name = "pseudonymize")]
    fn py_pseudonymize(
        &self,
        encrypted: &Bound<PyAny>,
        pseudonymization_info: &PyPseudonymizationInfo,
        public_key: &crate::keys::py::PyPseudonymSessionPublicKey,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(pseudonymization_info);
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);

        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.pseudonymize(&ep.0, &info, &pk, &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self.0.pseudonymize(&lep.0, &info, &pk, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "pseudonymize() requires EncryptedPseudonym or LongEncryptedPseudonym",
        ))
    }

    /// Polymorphic transcrypt that works with any transcryptable type.
    #[cfg(feature = "elgamal3")]
    #[pyo3(name = "transcrypt")]
    fn py_transcrypt(
        &self,
        encrypted: &Bound<PyAny>,
        transcryption_info: &PyTranscryptionInfo,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(transcryption_info);

        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.transcrypt(&ep.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            let result = self.0.transcrypt(&ea.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }

        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self.0.transcrypt(&lep.0, &info, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }

        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            let result = self.0.transcrypt(&lea.0, &info, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }

        if let Ok(er) = encrypted.extract::<PyEncryptedRecord>() {
            let result = self.0.transcrypt(&er.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedRecord(result))?.into_any());
        }

        #[cfg(feature = "long")]
        if let Ok(ler) = encrypted.extract::<PyLongEncryptedRecord>() {
            let result = self.0.transcrypt(&ler.0, &info, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedRecord(result))?.into_any());
        }

        #[cfg(feature = "json")]
        if let Ok(ej) = encrypted.extract::<PyEncryptedPEPJSONValue>() {
            let result = self.0.transcrypt(&ej.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedPEPJSONValue(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "transcrypt() requires EncryptedPseudonym, EncryptedAttribute, EncryptedRecord, LongEncryptedPseudonym, LongEncryptedAttribute, LongEncryptedRecord, or EncryptedPEPJSONValue",
        ))
    }

    /// Polymorphic transcrypt that works with any transcryptable type.
    /// Requires a public key in non-elgamal3 mode.
    #[cfg(not(feature = "elgamal3"))]
    #[pyo3(name = "transcrypt")]
    fn py_transcrypt(
        &self,
        encrypted: &Bound<PyAny>,
        transcryption_info: &PyTranscryptionInfo,
        public_key: &Bound<PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(transcryption_info);

        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            if let Ok(pk) = public_key.extract::<crate::keys::py::PyPseudonymSessionPublicKey>() {
                let pk = crate::keys::PseudonymSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&ep.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
            }
        }

        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            if let Ok(pk) = public_key.extract::<crate::keys::py::PyAttributeSessionPublicKey>() {
                let pk = crate::keys::AttributeSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&ea.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
            }
        }

        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            if let Ok(pk) = public_key.extract::<crate::keys::py::PyPseudonymSessionPublicKey>() {
                let pk = crate::keys::PseudonymSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&lep.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
            }
        }

        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            if let Ok(pk) = public_key.extract::<crate::keys::py::PyAttributeSessionPublicKey>() {
                let pk = crate::keys::AttributeSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&lea.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
            }
        }

        Err(PyTypeError::new_err(
            "transcrypt() in non-elgamal3 mode requires (encrypted, info, public_key) with matching pseudonym/attribute types",
        ))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDistributedTranscryptor>()?;
    Ok(())
}
