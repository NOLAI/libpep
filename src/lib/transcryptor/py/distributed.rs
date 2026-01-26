//! Python bindings for distributed transcryptor.

#[cfg(feature = "json")]
use crate::data::py::json::PyEncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::py::long::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::data::py::records::PyEncryptedRecord;
#[cfg(feature = "long")]
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
use pyo3::IntoPyObjectExt;

/// A distributed PEP transcryptor system with blinding factor support.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "DistributedTranscryptor")]
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
    #[pyo3(name = "pseudonymize")]
    fn py_pseudonymize(
        &self,
        encrypted: &Bound<PyAny>,
        pseudonymization_info: &PyPseudonymizationInfo,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let info = PseudonymizationInfo::from(pseudonymization_info);

        // Try EncryptedPseudonym
        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.pseudonymize(&ep.0, &info);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        // Try LongEncryptedPseudonym
        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self.0.pseudonymize(&lep.0, &info);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "pseudonymize() requires EncryptedPseudonym or LongEncryptedPseudonym",
        ))
    }

    /// Polymorphic transcrypt that works with any transcryptable type.
    #[pyo3(name = "transcrypt")]
    fn py_transcrypt(
        &self,
        encrypted: &Bound<PyAny>,
        transcryption_info: &PyTranscryptionInfo,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let info = TranscryptionInfo::from(transcryption_info);

        // Try EncryptedPseudonym
        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.transcrypt(&ep.0, &info);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        // Try EncryptedAttribute
        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            let result = self.0.transcrypt(&ea.0, &info);
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }

        // Try LongEncryptedPseudonym
        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self.0.transcrypt(&lep.0, &info);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }

        // Try LongEncryptedAttribute
        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            let result = self.0.transcrypt(&lea.0, &info);
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }

        // Try EncryptedRecord
        if let Ok(er) = encrypted.extract::<PyEncryptedRecord>() {
            let result = self.0.transcrypt(&er.0, &info);
            return Ok(Py::new(py, PyEncryptedRecord(result))?.into_any());
        }

        // Try LongEncryptedRecord
        #[cfg(feature = "long")]
        if let Ok(ler) = encrypted.extract::<PyLongEncryptedRecord>() {
            let result = self.0.transcrypt(&ler.0, &info);
            return Ok(Py::new(py, PyLongEncryptedRecord(result))?.into_any());
        }

        // Try EncryptedPEPJSONValue
        #[cfg(feature = "json")]
        if let Ok(ej) = encrypted.extract::<PyEncryptedPEPJSONValue>() {
            let result = self.0.transcrypt(&ej.0, &info);
            return Ok(Py::new(py, PyEncryptedPEPJSONValue(result))?.into_any());
        }

        Err(PyTypeError::new_err(
            "transcrypt() requires EncryptedPseudonym, EncryptedAttribute, EncryptedRecord, LongEncryptedPseudonym, LongEncryptedAttribute, LongEncryptedRecord, or EncryptedPEPJSONValue",
        ))
    }

    /// Polymorphic batch rekeying.
    #[cfg(feature = "batch")]
    #[pyo3(name = "rekey_batch")]
    fn py_rekey_batch(
        &self,
        encrypted: &Bound<PyAny>,
        rekey_info: &Bound<PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let mut rng = rand::rng();

        // Try Vec<EncryptedAttribute> with AttributeRekeyInfo
        if let Ok(eas) = encrypted.extract::<Vec<PyEncryptedAttribute>>() {
            if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
                let mut enc: Vec<_> = eas.into_iter().map(|e| e.0).collect();
                let result = self
                    .0
                    .rekey_batch(&mut enc, &AttributeRekeyInfo::from(&info), &mut rng)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
                let py_result: Vec<PyEncryptedAttribute> = result
                    .into_vec()
                    .into_iter()
                    .map(PyEncryptedAttribute)
                    .collect();
                return py_result.into_py_any(py);
            }
        }

        // Try Vec<LongEncryptedAttribute> with AttributeRekeyInfo
        #[cfg(feature = "long")]
        if let Ok(leas) = encrypted.extract::<Vec<PyLongEncryptedAttribute>>() {
            if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
                let mut enc: Vec<_> = leas.into_iter().map(|e| e.0).collect();
                let result = self
                    .0
                    .rekey_batch(&mut enc, &AttributeRekeyInfo::from(&info), &mut rng)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
                let py_result: Vec<PyLongEncryptedAttribute> = result
                    .into_vec()
                    .into_iter()
                    .map(PyLongEncryptedAttribute)
                    .collect();
                return py_result.into_py_any(py);
            }
        }

        Err(PyTypeError::new_err(
            "rekey_batch() requires (Vec[EncryptedAttribute] | Vec[LongEncryptedAttribute], AttributeRekeyInfo)",
        ))
    }

    /// Polymorphic batch pseudonymization.
    #[cfg(feature = "batch")]
    #[pyo3(name = "pseudonymize_batch")]
    fn py_pseudonymize_batch(
        &self,
        encrypted: &Bound<PyAny>,
        pseudonymization_info: &PyPseudonymizationInfo,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(pseudonymization_info);

        // Try Vec<EncryptedPseudonym>
        if let Ok(eps) = encrypted.extract::<Vec<PyEncryptedPseudonym>>() {
            let mut enc: Vec<_> = eps.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .pseudonymize_batch(&mut enc, &info, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyEncryptedPseudonym> = result
                .into_vec()
                .into_iter()
                .map(PyEncryptedPseudonym)
                .collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongEncryptedPseudonym>
        #[cfg(feature = "long")]
        if let Ok(leps) = encrypted.extract::<Vec<PyLongEncryptedPseudonym>>() {
            let mut enc: Vec<_> = leps.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .pseudonymize_batch(&mut enc, &info, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongEncryptedPseudonym> = result
                .into_vec()
                .into_iter()
                .map(PyLongEncryptedPseudonym)
                .collect();
            return py_result.into_py_any(py);
        }

        Err(PyTypeError::new_err(
            "pseudonymize_batch() requires Vec[EncryptedPseudonym] or Vec[LongEncryptedPseudonym]",
        ))
    }

    /// Polymorphic batch transcryption.
    #[cfg(feature = "batch")]
    #[pyo3(name = "transcrypt_batch")]
    fn py_transcrypt_batch(
        &self,
        encrypted: &Bound<PyAny>,
        transcryption_info: &PyTranscryptionInfo,
    ) -> PyResult<Py<PyAny>> {
        let py = encrypted.py();
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(transcryption_info);

        // Try Vec<EncryptedRecord>
        if let Ok(ers) = encrypted.extract::<Vec<PyEncryptedRecord>>() {
            let mut enc: Vec<_> = ers.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .transcrypt_batch(&mut enc, &info, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyEncryptedRecord> = result
                .into_vec()
                .into_iter()
                .map(PyEncryptedRecord)
                .collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<LongEncryptedRecord>
        #[cfg(feature = "long")]
        if let Ok(lers) = encrypted.extract::<Vec<PyLongEncryptedRecord>>() {
            let mut enc: Vec<_> = lers.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .transcrypt_batch(&mut enc, &info, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyLongEncryptedRecord> = result
                .into_vec()
                .into_iter()
                .map(PyLongEncryptedRecord)
                .collect();
            return py_result.into_py_any(py);
        }

        // Try Vec<EncryptedPEPJSONValue>
        #[cfg(feature = "json")]
        if let Ok(ejs) = encrypted.extract::<Vec<PyEncryptedPEPJSONValue>>() {
            let mut enc: Vec<_> = ejs.into_iter().map(|e| e.0).collect();
            let result = self
                .0
                .transcrypt_batch(&mut enc, &info, &mut rng)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let py_result: Vec<PyEncryptedPEPJSONValue> = result
                .into_vec()
                .into_iter()
                .map(PyEncryptedPEPJSONValue)
                .collect();
            return py_result.into_py_any(py);
        }

        Err(PyTypeError::new_err(
            "transcrypt_batch() requires Vec[EncryptedRecord], Vec[LongEncryptedRecord], or Vec[EncryptedPEPJSONValue]",
        ))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDistributedTranscryptor>()?;
    Ok(())
}
