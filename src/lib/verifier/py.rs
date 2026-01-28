//! Python bindings for the verifier.

use crate::data::py::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::py::commitments::{
    PyProvedPseudonymizationCommitments, PyProvedRekeyCommitments,
};
use crate::factors::py::contexts::{PyEncryptionContext, PyPseudonymizationDomain};
use crate::verifier::Verifier;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

#[cfg(feature = "verifiable")]
use crate::core::py::proved::{PyRSKFactorsProof, PyVerifiableRSK, PyVerifiableRekey};

/// A verifier for verifiable transcryption operations (Python).
#[derive(From, Into, Deref)]
#[pyclass(name = "Verifier")]
pub struct PyVerifier(Verifier);

#[pymethods]
impl PyVerifier {
    /// Create a new verifier with empty caches.
    #[new]
    pub fn new() -> Self {
        Self(Verifier::new())
    }

    /// Verify pseudonymization commitments.
    fn verify_pseudonymization_commitments(
        &self,
        commitments: &PyProvedPseudonymizationCommitments,
    ) -> bool {
        self.0
            .verify_pseudonymization_commitments(&commitments.inner)
    }

    /// Verify rekey commitments.
    fn verify_rekey_commitments(&self, commitments: &PyProvedRekeyCommitments) -> bool {
        self.0.verify_rekey_commitments(&commitments.inner)
    }

    /// Register pseudonymization commitments for caching.
    fn register_pseudonymization_commitments(
        &mut self,
        transcryptor_id: &str,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
        commitments: &PyProvedPseudonymizationCommitments,
    ) {
        self.0.register_pseudonymization_commitments(
            &transcryptor_id.to_string(),
            &domain_from.0,
            &domain_to.0,
            &context_from.0,
            &context_to.0,
            commitments.inner,
        );
    }

    /// Register attribute rekey commitments for caching.
    fn register_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: &str,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
        commitments: &PyProvedRekeyCommitments,
    ) {
        self.0.register_attribute_rekey_commitments(
            &transcryptor_id.to_string(),
            &context_from.0,
            &context_to.0,
            commitments.inner,
        );
    }

    /// Check if reshuffle commitments exist in cache.
    fn has_reshuffle_commitments(
        &self,
        transcryptor_id: &str,
        domain: &PyPseudonymizationDomain,
    ) -> bool {
        self.0.has_reshuffle_commitments(transcryptor_id, &domain.0)
    }

    /// Check if pseudonym rekey commitments exist in cache.
    fn has_pseudonym_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context: &PyEncryptionContext,
    ) -> bool {
        self.0
            .has_pseudonym_rekey_commitments(transcryptor_id, &context.0)
    }

    /// Check if attribute rekey commitments exist in cache.
    fn has_attribute_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context: &PyEncryptionContext,
    ) -> bool {
        self.0
            .has_attribute_rekey_commitments(transcryptor_id, &context.0)
    }

    /// Clear all cached commitments.
    fn clear_cache(&mut self) {
        self.0.clear_cache();
    }

    /// Get cache size.
    fn cache_size(&self) -> usize {
        self.0.cache().total_count()
    }

    /// Verify a pseudonymization operation with commitments.
    #[cfg(feature = "verifiable")]
    fn verify_pseudonymization(
        &self,
        original: &PyEncryptedPseudonym,
        result: &PyEncryptedPseudonym,
        operation_proof: &PyVerifiableRSK,
        factors_proof: &PyRSKFactorsProof,
        commitments: &PyProvedPseudonymizationCommitments,
    ) -> bool {
        self.0.verify_pseudonymization(
            &original.0,
            &result.0,
            &operation_proof.inner,
            &factors_proof.inner,
            &commitments.inner,
        )
    }

    /// Verify a pseudonym rekey operation with commitments.
    #[cfg(feature = "verifiable")]
    fn verify_pseudonym_rekey(
        &self,
        original: &PyEncryptedPseudonym,
        result: &PyEncryptedPseudonym,
        proof: &PyVerifiableRekey,
        commitments: &PyProvedRekeyCommitments,
    ) -> bool {
        self.0
            .verify_pseudonym_rekey(&original.0, &result.0, &proof.inner, &commitments.inner)
    }

    /// Verify an attribute rekey operation with commitments.
    #[cfg(feature = "verifiable")]
    fn verify_attribute_rekey(
        &self,
        original: &PyEncryptedAttribute,
        result: &PyEncryptedAttribute,
        proof: &PyVerifiableRekey,
        commitments: &PyProvedRekeyCommitments,
    ) -> bool {
        self.0
            .verify_attribute_rekey(&original.0, &result.0, &proof.inner, &commitments.inner)
    }
}

impl Default for PyVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn register_verifier_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifier>()?;
    Ok(())
}
