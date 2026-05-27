//! Python bindings for transcryptor types.

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
#[cfg(not(feature = "elgamal3"))]
use crate::keys::py::{PyAttributeSessionPublicKey, PyPseudonymSessionPublicKey};
use crate::transcryptor::Transcryptor;
use derive_more::{Deref, From, Into};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

/// A PEP transcryptor system.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "Transcryptor", from_py_object)]
pub struct PyTranscryptor(pub(crate) Transcryptor);

#[pymethods]
impl PyTranscryptor {
    #[new]
    fn new(pseudonymisation_secret: &str, rekeying_secret: &str) -> Self {
        Self(Transcryptor::new(
            PseudonymizationSecret::from(pseudonymisation_secret.as_bytes().to_vec()),
            EncryptionSecret::from(rekeying_secret.as_bytes().to_vec()),
        ))
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

        // Try EncryptedPseudonym
        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.pseudonymize(&ep.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        // Try LongEncryptedPseudonym
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
        public_key: &PyPseudonymSessionPublicKey,
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

        // Try EncryptedPseudonym
        if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
            let result = self.0.transcrypt(&ep.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }

        // Try EncryptedAttribute
        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            let result = self.0.transcrypt(&ea.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }

        // Try LongEncryptedPseudonym
        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            let result = self.0.transcrypt(&lep.0, &info, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }

        // Try LongEncryptedAttribute
        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            let result = self.0.transcrypt(&lea.0, &info, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }

        // Try EncryptedRecord
        if let Ok(er) = encrypted.extract::<PyEncryptedRecord>() {
            let result = self.0.transcrypt(&er.0, &info, &mut rng);
            return Ok(Py::new(py, PyEncryptedRecord(result))?.into_any());
        }

        // Try LongEncryptedRecord
        #[cfg(feature = "long")]
        if let Ok(ler) = encrypted.extract::<PyLongEncryptedRecord>() {
            let result = self.0.transcrypt(&ler.0, &info, &mut rng);
            return Ok(Py::new(py, PyLongEncryptedRecord(result))?.into_any());
        }

        // Try EncryptedPEPJSONValue
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
    /// In non-elgamal3 builds the recipient public key (or session keys for record/json) is required.
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
            if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
                let pk = crate::keys::PseudonymSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&ep.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
            }
        }

        if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
            if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
                let pk = crate::keys::AttributeSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&ea.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
            }
        }

        #[cfg(feature = "long")]
        if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
            if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
                let pk = crate::keys::PseudonymSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&lep.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
            }
        }

        #[cfg(feature = "long")]
        if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
            if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
                let pk = crate::keys::AttributeSessionPublicKey::from(pk.0 .0);
                let result = self.0.transcrypt(&lea.0, &info, &pk, &mut rng);
                return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
            }
        }

        Err(PyTypeError::new_err(
            "transcrypt() in non-elgamal3 mode requires (encrypted, info, public_key) with matching pseudonym/attribute types",
        ))
    }

    /// Generate commitment proofs for pseudonymization factors.
    #[cfg(feature = "verifiable")]
    fn pseudonymization_commitments(
        &self,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::factors::py::commitments::PyVerifiablePseudonymizationCommitments {
        use crate::factors::py::commitments::PyVerifiablePseudonymizationCommitments;
        let info = self.pseudonymization_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        );
        PyVerifiablePseudonymizationCommitments {
            inner: Transcryptor::pseudonymization_commitment(&info),
        }
    }

    /// Generate commitment proofs for attribute rekey factors.
    #[cfg(feature = "verifiable")]
    fn attribute_rekey_commitments(
        &self,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::factors::py::commitments::PyVerifiableRekeyCommitments {
        use crate::factors::py::commitments::PyVerifiableRekeyCommitments;
        let info = self.attribute_rekey_info(&session_from.0, &session_to.0);
        PyVerifiableRekeyCommitments {
            inner: Transcryptor::attribute_rekey_commitment(&info),
        }
    }

    /// Generate commitment proofs for pseudonym rekey factors.
    #[cfg(feature = "verifiable")]
    fn pseudonym_rekey_commitments(
        &self,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::factors::py::commitments::PyVerifiableRekeyCommitments {
        use crate::factors::py::commitments::PyVerifiableRekeyCommitments;
        let info = self.pseudonym_rekey_info(&session_from.0, &session_to.0);
        PyVerifiableRekeyCommitments {
            inner: Transcryptor::pseudonym_rekey_commitment(&info),
        }
    }

    /// Perform verifiable pseudonymization.
    ///
    /// Returns the operation proof (self-contained — no separate factors
    /// proof is needed in the forward-direction construction).
    #[cfg(all(feature = "verifiable", feature = "elgamal3"))]
    fn verifiable_pseudonymize(
        &self,
        encrypted: &PyEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
    ) -> crate::core::py::verifiable::PyVerifiableRRSK {
        use crate::data::verifiable::traits::VerifiablePseudonymizable;

        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(pseudo_info);
        let operation_proof = encrypted.0.verifiable_pseudonymize(&info, &mut rng);

        crate::core::py::verifiable::PyVerifiableRRSK {
            inner: operation_proof.0,
        }
    }

    #[cfg(all(feature = "verifiable", not(feature = "elgamal3")))]
    fn verifiable_pseudonymize(
        &self,
        encrypted: &PyEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
        public_key: &PyPseudonymSessionPublicKey,
    ) -> crate::core::py::verifiable::PyVerifiableRRSK {
        use crate::data::verifiable::traits::VerifiablePseudonymizable;

        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(pseudo_info);
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let operation_proof = encrypted.0.verifiable_pseudonymize(&info, &pk, &mut rng);

        crate::core::py::verifiable::PyVerifiableRRSK {
            inner: operation_proof.0,
        }
    }

    /// Perform verifiable attribute rekey.
    ///
    /// Returns the operation proof.
    #[cfg(feature = "verifiable")]
    fn verifiable_attribute_rekey(
        &self,
        encrypted: &PyEncryptedAttribute,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> crate::core::py::verifiable::PyVerifiableRekey {
        use crate::data::verifiable::traits::VerifiableRekeyable;

        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(rekey_info);
        let operation_proof = encrypted.0.verifiable_rekey(&info, &mut rng);

        crate::core::py::verifiable::PyVerifiableRekey {
            inner: operation_proof.0,
        }
    }

    /// Perform verifiable pseudonym rekey.
    ///
    /// Returns the operation proof.
    #[cfg(feature = "verifiable")]
    fn verifiable_pseudonym_rekey(
        &self,
        encrypted: &PyEncryptedPseudonym,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::core::py::verifiable::PyVerifiableRekey {
        use crate::data::verifiable::traits::VerifiableRekeyable;

        let mut rng = rand::rng();
        let info = self.pseudonym_rekey_info(&session_from.0, &session_to.0);
        let operation_proof = encrypted.0.verifiable_rekey(&info, &mut rng);

        crate::core::py::verifiable::PyVerifiableRekey {
            inner: operation_proof.0,
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTranscryptor>()?;
    Ok(())
}
