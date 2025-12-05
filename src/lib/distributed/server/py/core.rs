use super::super::transcryptor::PEPSystem;
use super::setup::PyBlindingFactor;
use crate::core::data::{EncryptedAttribute, EncryptedPseudonym};
#[cfg(feature = "long")]
use crate::core::long::data::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "long")]
use crate::core::long::py::data::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::core::py::data::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::core::transcryption::contexts::*;
use crate::core::transcryption::py::contexts::{
    PyAttributeRekeyInfo, PyEncryptionContext, PyPseudonymRekeyFactor, PyPseudonymizationDomain,
    PyPseudonymizationInfo, PyTranscryptionInfo,
};
use crate::core::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::distributed::client::py::keys::{
    PyAttributeSessionKeyShare, PyPseudonymSessionKeyShare, PySessionKeyShares,
};
use crate::distributed::server::setup::BlindingFactor;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

/// A PEP transcryptor system.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "PEPSystem")]
pub struct PyPEPSystem(PEPSystem);

#[pymethods]
impl PyPEPSystem {
    #[new]
    fn new(
        pseudonymisation_secret: &str,
        rekeying_secret: &str,
        blinding_factor: &PyBlindingFactor,
    ) -> Self {
        Self(PEPSystem::new(
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

    #[pyo3(name = "rekey")]
    fn py_rekey(
        &self,
        encrypted: &PyEncryptedAttribute,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> PyEncryptedAttribute {
        PyEncryptedAttribute::from(self.rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)))
    }

    #[pyo3(name = "pseudonymize")]
    fn py_pseudonymize(
        &self,
        encrypted: &PyEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
    ) -> PyEncryptedPseudonym {
        PyEncryptedPseudonym::from(
            self.pseudonymize(&encrypted.0, &PseudonymizationInfo::from(pseudo_info)),
        )
    }

    #[pyo3(name = "rekey_batch")]
    fn py_rekey_batch(
        &self,
        encrypted: Vec<PyEncryptedAttribute>,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> Vec<PyEncryptedAttribute> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<EncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self.rekey_batch(
            &mut encrypted,
            &AttributeRekeyInfo::from(rekey_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(PyEncryptedAttribute::from)
            .collect()
    }

    #[pyo3(name = "pseudonymize_batch")]
    fn py_pseudonymize_batch(
        &self,
        encrypted: Vec<PyEncryptedPseudonym>,
        pseudonymization_info: &PyPseudonymizationInfo,
    ) -> Vec<PyEncryptedPseudonym> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<EncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self.pseudonymize_batch(
            &mut encrypted,
            &PseudonymizationInfo::from(pseudonymization_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(PyEncryptedPseudonym::from)
            .collect()
    }

    // Long data type methods

    /// Rekey a long encrypted attribute from one session to another.
    #[cfg(feature = "long")]
    #[pyo3(name = "rekey_long")]
    fn py_rekey_long(
        &self,
        encrypted: &PyLongEncryptedAttribute,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> PyLongEncryptedAttribute {
        PyLongEncryptedAttribute::from(
            self.rekey_long(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)),
        )
    }

    /// Pseudonymize a long encrypted pseudonym from one domain/session to another.
    #[cfg(feature = "long")]
    #[pyo3(name = "pseudonymize_long")]
    fn py_pseudonymize_long(
        &self,
        encrypted: &PyLongEncryptedPseudonym,
        pseudonymization_info: &PyPseudonymizationInfo,
    ) -> PyLongEncryptedPseudonym {
        PyLongEncryptedPseudonym::from(self.pseudonymize_long(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudonymization_info),
        ))
    }

    /// Rekey a batch of long encrypted attributes from one session to another.
    #[cfg(all(feature = "long", feature = "batch"))]
    #[pyo3(name = "rekey_long_batch")]
    fn py_rekey_long_batch(
        &self,
        encrypted: Vec<PyLongEncryptedAttribute>,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> Vec<PyLongEncryptedAttribute> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<LongEncryptedAttribute> =
            encrypted.into_iter().map(|e| e.0).collect();
        let result = self.rekey_long_batch(
            &mut encrypted,
            &AttributeRekeyInfo::from(rekey_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(PyLongEncryptedAttribute::from)
            .collect()
    }

    /// Pseudonymize a batch of long encrypted pseudonyms from one domain/session to another.
    #[cfg(all(feature = "long", feature = "batch"))]
    #[pyo3(name = "pseudonymize_long_batch")]
    fn py_pseudonymize_long_batch(
        &self,
        encrypted: Vec<PyLongEncryptedPseudonym>,
        pseudonymization_info: &PyPseudonymizationInfo,
    ) -> Vec<PyLongEncryptedPseudonym> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<LongEncryptedPseudonym> =
            encrypted.into_iter().map(|e| e.0).collect();
        let result = self.pseudonymize_long_batch(
            &mut encrypted,
            &PseudonymizationInfo::from(pseudonymization_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(PyLongEncryptedPseudonym::from)
            .collect()
    }

    /// Transcrypt an EncryptedPEPJSONValue from one context to another.
    ///
    /// Args:
    ///     encrypted: The EncryptedPEPJSONValue to transcrypt
    ///     transcryption_info: The transcryption information
    ///
    /// Returns:
    ///     A transcrypted EncryptedPEPJSONValue
    #[cfg(feature = "json")]
    #[pyo3(name = "transcrypt_json")]
    fn transcrypt_json(
        &self,
        encrypted: &crate::core::json::py::PyEncryptedPEPJSONValue,
        transcryption_info: &crate::core::transcryption::py::contexts::PyTranscryptionInfo,
    ) -> crate::core::json::py::PyEncryptedPEPJSONValue {
        use crate::core::transcryption::contexts::TranscryptionInfo;
        let transcrypted = self
            .0
            .transcrypt_json(&encrypted.0, &TranscryptionInfo::from(transcryption_info));
        crate::core::json::py::PyEncryptedPEPJSONValue(transcrypted)
    }

    /// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
    ///
    /// Args:
    ///     values: List of EncryptedPEPJSONValue objects
    ///     transcryption_info: The transcryption information
    ///
    /// Returns:
    ///     A shuffled list of transcrypted EncryptedPEPJSONValue objects
    #[cfg(all(feature = "json", feature = "batch"))]
    #[pyo3(name = "transcrypt_json_batch")]
    fn transcrypt_json_batch(
        &self,
        values: Vec<crate::core::json::py::PyEncryptedPEPJSONValue>,
        transcryption_info: &crate::core::transcryption::py::contexts::PyTranscryptionInfo,
    ) -> PyResult<Vec<crate::core::json::py::PyEncryptedPEPJSONValue>> {
        use crate::core::transcryption::contexts::TranscryptionInfo;
        let mut rng = rand::rng();
        let rust_values: Vec<_> = values.into_iter().map(|v| v.0).collect();
        let transcrypted = self
            .0
            .transcrypt_json_batch(
                rust_values,
                &TranscryptionInfo::from(transcryption_info),
                &mut rng,
            )
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(transcrypted
            .into_iter()
            .map(crate::core::json::py::PyEncryptedPEPJSONValue)
            .collect())
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPEPSystem>()?;
    Ok(())
}
