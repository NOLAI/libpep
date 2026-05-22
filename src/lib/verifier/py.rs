//! Python bindings for the verifier.

use crate::data::py::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::py::commitments::{
    PyVerifiablePseudonymizationCommitments, PyVerifiableRekeyCommitments,
};
use crate::factors::py::contexts::{PyEncryptionContext, PyPseudonymizationDomain};
use crate::verifier::Verifier;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

#[cfg(feature = "verifiable")]
use crate::core::py::verifiable::{PyVerifiableRSK, PyVerifiableRekey};

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

    /// Register pseudonymization commitments (combined per transition) for
    /// caching. With the forward-only construction there is no separate
    /// proof-of-well-formedness to verify; the per-message proofs bind the
    /// operation directly to these commitments.
    fn register_pseudonymization_commitments(
        &mut self,
        transcryptor_id: &str,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
        commitments: &PyVerifiablePseudonymizationCommitments,
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
        commitments: &PyVerifiableRekeyCommitments,
    ) {
        self.0.register_attribute_rekey_commitments(
            &transcryptor_id.to_string(),
            &context_from.0,
            &context_to.0,
            commitments.inner,
        );
    }

    /// Register pseudonym rekey commitments for caching.
    fn register_pseudonym_rekey_commitments(
        &mut self,
        transcryptor_id: &str,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
        commitments: &PyVerifiableRekeyCommitments,
    ) {
        self.0.register_pseudonym_rekey_commitments(
            &transcryptor_id.to_string(),
            &context_from.0,
            &context_to.0,
            commitments.inner,
        );
    }

    /// Check if pseudonymization commitments exist for a transition.
    fn has_pseudonymization_commitments(
        &self,
        transcryptor_id: &str,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> bool {
        self.0.has_pseudonymization_commitments(
            transcryptor_id,
            &domain_from.0,
            &domain_to.0,
            &context_from.0,
            &context_to.0,
        )
    }

    /// Check if pseudonym rekey commitments exist for a transition.
    fn has_pseudonym_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> bool {
        self.0
            .has_pseudonym_rekey_commitments(transcryptor_id, &context_from.0, &context_to.0)
    }

    /// Check if attribute rekey commitments exist for a transition.
    fn has_attribute_rekey_commitments(
        &self,
        transcryptor_id: &str,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> bool {
        self.0
            .has_attribute_rekey_commitments(transcryptor_id, &context_from.0, &context_to.0)
    }

    /// Clear all cached commitments.
    fn clear_cache(&mut self) {
        self.0.clear_cache();
    }

    /// Get cache size.
    fn cache_size(&self) -> usize {
        self.0.cache().total_count()
    }

    /// Verify a pseudonymization operation against the combined commitments.
    #[cfg(all(feature = "verifiable", feature = "elgamal3"))]
    fn verify_pseudonymization(
        &self,
        original: &PyEncryptedPseudonym,
        result: &PyEncryptedPseudonym,
        operation_proof: &PyVerifiableRSK,
        commitments: &PyVerifiablePseudonymizationCommitments,
    ) -> bool {
        self.0.verify_pseudonymization(
            &original.0,
            &result.0,
            &operation_proof.inner,
            &commitments.inner,
        )
    }

    /// Verify a pseudonymization operation against the combined commitments.
    /// In non-elgamal3 builds the recipient public key the original ciphertext
    /// was encrypted under must be supplied so that the inner rerandomize step
    /// can be verified.
    #[cfg(all(feature = "verifiable", not(feature = "elgamal3")))]
    fn verify_pseudonymization(
        &self,
        original: &PyEncryptedPseudonym,
        result: &PyEncryptedPseudonym,
        operation_proof: &PyVerifiableRSK,
        public_key: &crate::keys::py::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitments,
    ) -> bool {
        use crate::keys::PublicKey;
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.0.verify_pseudonymization(
            &original.0,
            &result.0,
            &operation_proof.inner,
            pk.value(),
            &commitments.inner,
        )
    }

    /// Verify a pseudonym rekey operation against the rekey commitment.
    #[cfg(feature = "verifiable")]
    fn verify_pseudonym_rekey(
        &self,
        original: &PyEncryptedPseudonym,
        result: &PyEncryptedPseudonym,
        proof: &PyVerifiableRekey,
        commitments: &PyVerifiableRekeyCommitments,
    ) -> bool {
        self.0
            .verify_pseudonym_rekey(&original.0, &result.0, &proof.inner, &commitments.inner)
    }

    /// Verify an attribute rekey operation against the rekey commitment.
    #[cfg(feature = "verifiable")]
    fn verify_attribute_rekey(
        &self,
        original: &PyEncryptedAttribute,
        result: &PyEncryptedAttribute,
        proof: &PyVerifiableRekey,
        commitments: &PyVerifiableRekeyCommitments,
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

#[allow(dead_code)]
pub(crate) fn register_verifier_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifier>()?;
    Ok(())
}
