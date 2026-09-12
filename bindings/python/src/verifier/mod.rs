//! Python bindings for the verifier.

use crate::contexts::{PyEncryptionContext, PyPseudonymizationDomain};
use crate::data::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::elgamal::verifiable::PyVerifiableRRSK;
use crate::elgamal::verifiable::PyVerifiableRekey;
use crate::factors::commitments::{
    PyVerifiablePseudonymizationCommitment, PyVerifiableRekeyCommitment,
    PyVerifiableTranscryptionCommitment,
};
use derive_more::{Deref, From, Into};
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;
use libpep::verifier::Verifier;
use pyo3::prelude::*;

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

    /// Create a new verifier with empty caches, each capped at
    /// `max_entries` commitments. Once full, `register_*_commitments` raises
    /// a typed cache-full error.
    #[staticmethod]
    pub fn with_cache_capacity(max_entries: usize) -> Self {
        Self(Verifier::with_cache_capacity(max_entries))
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
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<()> {
        self.0
            .register_pseudonymization_commitments(
                &transcryptor_id.to_string(),
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
                commitments.inner,
            )
            .map_err(crate::errors::register_commitments_err_to_py)
    }

    /// Register attribute rekey commitments for caching.
    fn register_attribute_rekey_commitments(
        &mut self,
        transcryptor_id: &str,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<()> {
        self.0
            .register_attribute_rekey_commitments(
                &transcryptor_id.to_string(),
                &context_from.0,
                &context_to.0,
                commitments.inner,
            )
            .map_err(crate::errors::register_commitments_err_to_py)
    }

    /// Register pseudonym rekey commitments for caching.
    fn register_pseudonym_rekey_commitments(
        &mut self,
        transcryptor_id: &str,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<()> {
        self.0
            .register_pseudonym_rekey_commitments(
                &transcryptor_id.to_string(),
                &context_from.0,
                &context_to.0,
                commitments.inner,
            )
            .map_err(crate::errors::register_commitments_err_to_py)
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

    /// Verify a pseudonymization operation against the combined commitments,
    /// returning the reconstructed pseudonym on success or raising on failure.
    #[cfg(all(feature = "verifiable", feature = "elgamal3"))]
    fn verify_pseudonymization(
        &self,
        original: &PyEncryptedPseudonym,
        operation_proof: &PyVerifiableRRSK,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyEncryptedPseudonym> {
        let proof =
            libpep::data::verifiable::simple::PseudonymPseudonymizationProof(operation_proof.inner);
        self.0
            .verified_reconstruct_pseudonymization(&original.0, &proof, &commitments.inner)
            .map(PyEncryptedPseudonym)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Verify a pseudonymization operation against the combined commitments,
    /// returning the reconstructed pseudonym on success. In non-elgamal3
    /// builds the recipient public key the original ciphertext was encrypted
    /// under must be supplied so that the inner rerandomize step can be
    /// verified.
    #[cfg(all(feature = "verifiable", not(feature = "elgamal3")))]
    fn verify_pseudonymization(
        &self,
        original: &PyEncryptedPseudonym,
        operation_proof: &PyVerifiableRRSK,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyEncryptedPseudonym> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let proof =
            libpep::data::verifiable::simple::PseudonymPseudonymizationProof(operation_proof.inner);
        self.0
            .verified_reconstruct_pseudonymization(&original.0, &proof, &pk, &commitments.inner)
            .map(PyEncryptedPseudonym)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Verify a pseudonym rekey operation against the rekey commitment.
    #[cfg(feature = "verifiable")]
    fn verify_pseudonym_rekey(
        &self,
        original: &PyEncryptedPseudonym,
        proof: &PyVerifiableRekey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyEncryptedPseudonym> {
        let wrapped = libpep::data::verifiable::simple::PseudonymRekeyProof(proof.inner);
        self.0
            .verified_reconstruct_rekey(&original.0, &wrapped, &commitments.inner)
            .map(PyEncryptedPseudonym)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Verify an attribute rekey operation against the rekey commitment.
    #[cfg(feature = "verifiable")]
    fn verify_attribute_rekey(
        &self,
        original: &PyEncryptedAttribute,
        proof: &PyVerifiableRekey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyEncryptedAttribute> {
        let wrapped = libpep::data::verifiable::simple::AttributeRekeyProof(proof.inner);
        self.0
            .verified_reconstruct_rekey(&original.0, &wrapped, &commitments.inner)
            .map(PyEncryptedAttribute)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Verify a record transcryption operation, returning the reconstructed
    /// record on success. Pseudonym fields are checked by RRSK, attribute
    /// fields by rekey; the `commitments` bundle covers both.
    #[cfg(all(feature = "verifiable", feature = "elgamal3"))]
    fn verify_record_transcryption(
        &self,
        original: &crate::data::records::PyEncryptedRecord,
        proof: &crate::data::records::PyRecordTranscryptionProof,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::records::PyEncryptedRecord> {
        self.0
            .verified_reconstruct_transcryption(&original.0, &proof.inner, &commitments.inner)
            .map(crate::data::records::PyEncryptedRecord)
            .map_err(crate::errors::verify_err_to_py)
    }

    #[cfg(all(feature = "verifiable", not(feature = "elgamal3")))]
    fn verify_record_transcryption(
        &self,
        original: &crate::data::records::PyEncryptedRecord,
        proof: &crate::data::records::PyRecordTranscryptionProof,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::records::PyEncryptedRecord> {
        let sk = libpep::keys::SessionKeys::from(session_keys.clone());
        self.0
            .verified_reconstruct_transcryption(&original.0, &proof.inner, &sk, &commitments.inner)
            .map(crate::data::records::PyEncryptedRecord)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Verify a long record transcryption operation, returning the
    /// reconstructed long record on success.
    #[cfg(all(feature = "verifiable", feature = "long", feature = "elgamal3"))]
    fn verify_long_record_transcryption(
        &self,
        original: &crate::data::records::PyLongEncryptedRecord,
        proof: &crate::data::records::PyLongRecordTranscryptionProof,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::records::PyLongEncryptedRecord> {
        self.0
            .verified_reconstruct_transcryption(&original.0, &proof.inner, &commitments.inner)
            .map(crate::data::records::PyLongEncryptedRecord)
            .map_err(crate::errors::verify_err_to_py)
    }

    #[cfg(all(feature = "verifiable", feature = "long", not(feature = "elgamal3")))]
    fn verify_long_record_transcryption(
        &self,
        original: &crate::data::records::PyLongEncryptedRecord,
        proof: &crate::data::records::PyLongRecordTranscryptionProof,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::records::PyLongEncryptedRecord> {
        let sk = libpep::keys::SessionKeys::from(session_keys.clone());
        self.0
            .verified_reconstruct_transcryption(&original.0, &proof.inner, &sk, &commitments.inner)
            .map(crate::data::records::PyLongEncryptedRecord)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Cache-backed pseudonymization verification: looks up the registered
    /// commitments by transition and verifies the proof against them. Raises
    /// `ValueError` if no commitments are registered for that transition or
    /// the proof does not verify.
    #[cfg(all(feature = "verifiable", feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    fn verify_pseudonymization_cached(
        &self,
        transcryptor_id: &str,
        original: &PyEncryptedPseudonym,
        operation_proof: &PyVerifiableRRSK,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> PyResult<PyEncryptedPseudonym> {
        let proof =
            libpep::data::verifiable::simple::PseudonymPseudonymizationProof(operation_proof.inner);
        self.0
            .verified_reconstruct_pseudonymization_cached(
                transcryptor_id,
                &original.0,
                &proof,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(PyEncryptedPseudonym)
            .map_err(crate::errors::verify_err_to_py)
    }

    #[cfg(all(feature = "verifiable", not(feature = "elgamal3")))]
    #[allow(clippy::too_many_arguments)]
    fn verify_pseudonymization_cached(
        &self,
        transcryptor_id: &str,
        original: &PyEncryptedPseudonym,
        operation_proof: &PyVerifiableRRSK,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> PyResult<PyEncryptedPseudonym> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let proof =
            libpep::data::verifiable::simple::PseudonymPseudonymizationProof(operation_proof.inner);
        self.0
            .verified_reconstruct_pseudonymization_cached(
                transcryptor_id,
                &original.0,
                &proof,
                &pk,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(PyEncryptedPseudonym)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Cache-backed pseudonym rekey verification.
    #[cfg(feature = "verifiable")]
    fn verify_pseudonym_rekey_cached(
        &self,
        transcryptor_id: &str,
        original: &PyEncryptedPseudonym,
        proof: &PyVerifiableRekey,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> PyResult<PyEncryptedPseudonym> {
        let wrapped = libpep::data::verifiable::simple::PseudonymRekeyProof(proof.inner);
        self.0
            .verified_reconstruct_pseudonym_rekey_cached(
                transcryptor_id,
                &original.0,
                &wrapped,
                &context_from.0,
                &context_to.0,
            )
            .map(PyEncryptedPseudonym)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Cache-backed attribute rekey verification.
    #[cfg(feature = "verifiable")]
    fn verify_attribute_rekey_cached(
        &self,
        transcryptor_id: &str,
        original: &PyEncryptedAttribute,
        proof: &PyVerifiableRekey,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> PyResult<PyEncryptedAttribute> {
        let wrapped = libpep::data::verifiable::simple::AttributeRekeyProof(proof.inner);
        self.0
            .verified_reconstruct_attribute_rekey_cached(
                transcryptor_id,
                &original.0,
                &wrapped,
                &context_from.0,
                &context_to.0,
            )
            .map(PyEncryptedAttribute)
            .map_err(crate::errors::verify_err_to_py)
    }
}

impl Default for PyVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Verifiable-derivation methods (master keys, blinding commitments, session-
// key-share verification, cached transcryption).
// ---------------------------------------------------------------------------
#[cfg(feature = "verifiable-derivation")]
#[pymethods]
impl PyVerifier {
    /// Register blinding commitments for a transcryptor.
    fn register_blinding_commitments(
        &mut self,
        transcryptor_id: &str,
        commitments: &crate::keys::distribution::proofs::PyBlindingCommitments,
    ) -> PyResult<()> {
        self.0
            .register_blinding_commitments(transcryptor_id.to_string(), commitments.inner)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Check if blinding commitments are registered for a transcryptor.
    fn has_blinding_commitments(&self, transcryptor_id: &str) -> bool {
        self.0.has_blinding_commitments(transcryptor_id)
    }

    /// Retrieve the blinding commitments for a transcryptor, if registered.
    fn get_blinding_commitments(
        &self,
        transcryptor_id: &str,
    ) -> Option<crate::keys::distribution::proofs::PyBlindingCommitments> {
        self.0
            .get_blinding_commitments(transcryptor_id)
            .copied()
            .map(|inner| crate::keys::distribution::proofs::PyBlindingCommitments { inner })
    }

    /// Register master pseudonymization and rekeying public keys for a transcryptor.
    fn register_master_keys(
        &mut self,
        transcryptor_id: &str,
        pseudonym_master_key: &crate::factors::verifiable::PyMasterPseudonymizationPublicKey,
        rekey_master_key: &crate::factors::verifiable::PyMasterRekeyingPublicKey,
    ) -> PyResult<()> {
        self.0
            .register_master_keys(
                transcryptor_id.to_string(),
                pseudonym_master_key.inner,
                rekey_master_key.inner,
            )
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Check if master keys are registered for a transcryptor.
    fn has_master_keys(&self, transcryptor_id: &str) -> bool {
        self.0.has_master_keys(transcryptor_id)
    }

    /// Retrieve the master pseudonymization public key for a transcryptor, if registered.
    fn get_master_pseudonym_key(
        &self,
        transcryptor_id: &str,
    ) -> Option<crate::factors::verifiable::PyMasterPseudonymizationPublicKey> {
        self.0
            .get_master_pseudonym_key(transcryptor_id)
            .copied()
            .map(|inner| crate::factors::verifiable::PyMasterPseudonymizationPublicKey { inner })
    }

    /// Retrieve the master rekeying public key for a transcryptor, if registered.
    fn get_master_rekey_key(
        &self,
        transcryptor_id: &str,
    ) -> Option<crate::factors::verifiable::PyMasterRekeyingPublicKey> {
        self.0
            .get_master_rekey_key(transcryptor_id)
            .copied()
            .map(|inner| crate::factors::verifiable::PyMasterRekeyingPublicKey { inner })
    }

    /// Verify a session-key-share proof against a stored blinding commitment
    /// and an explicitly supplied rekey commitment.
    fn verify_session_key_share_with_commitment(
        &self,
        transcryptor_id: &str,
        rekey_commitment: &crate::elgamal::arithmetic::group_elements::PyGroupElement,
        for_pseudonym: bool,
        proof: &crate::keys::distribution::proofs::PySessionKeyShareProof,
    ) -> PyResult<()> {
        self.0
            .verify_session_key_share_with_commitment(
                transcryptor_id,
                &rekey_commitment.0,
                for_pseudonym,
                &proof.inner,
            )
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Cache-backed record transcryption verification (elgamal3 build).
    #[cfg(feature = "elgamal3")]
    #[allow(clippy::too_many_arguments)]
    fn verify_record_transcryption_cached(
        &self,
        transcryptor_id: &str,
        original: &crate::data::records::PyEncryptedRecord,
        proof: &crate::data::records::PyRecordTranscryptionProof,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> PyResult<crate::data::records::PyEncryptedRecord> {
        self.0
            .verified_reconstruct_transcryption_cached(
                transcryptor_id,
                &original.0,
                &proof.inner,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(crate::data::records::PyEncryptedRecord)
            .map_err(crate::errors::verify_err_to_py)
    }

    /// Cache-backed record transcryption verification (non-elgamal3 build).
    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    fn verify_record_transcryption_cached(
        &self,
        transcryptor_id: &str,
        original: &crate::data::records::PyEncryptedRecord,
        proof: &crate::data::records::PyRecordTranscryptionProof,
        session_keys: &crate::keys::PySessionKeys,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        context_from: &PyEncryptionContext,
        context_to: &PyEncryptionContext,
    ) -> PyResult<crate::data::records::PyEncryptedRecord> {
        let sk = libpep::keys::SessionKeys::from(session_keys.clone());
        self.0
            .verified_reconstruct_transcryption_cached(
                transcryptor_id,
                &original.0,
                &proof.inner,
                &sk,
                &domain_from.0,
                &domain_to.0,
                &context_from.0,
                &context_to.0,
            )
            .map(crate::data::records::PyEncryptedRecord)
            .map_err(crate::errors::verify_err_to_py)
    }
}

// ---------------------------------------------------------------------------
// Batch-proof verification methods
//
// Mirrors the per-message `verify_*` methods above but operates on an
// `EncryptedBatch<E>` (wrapped as `Py*Batch`) and the corresponding hoisted
// batch proof. The cfg layout matches the inherent
// `*BatchProof::verified_reconstruct_batch` impls in
// `libpep::data::verifiable`.
// ---------------------------------------------------------------------------
#[cfg(all(feature = "batch", feature = "verifiable"))]
#[pymethods]
impl PyVerifier {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_pseudonymization_batch(
        &self,
        original: &crate::data::batch::PyPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<crate::data::batch::PyPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.inner)
            .map(crate::data::batch::PyPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verify_pseudonymization_batch(
        &self,
        original: &crate::data::batch::PyPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<crate::data::batch::PyPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.inner)
            .map(crate::data::batch::PyPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(feature = "elgamal3")]
    fn verify_pseudonymization_batch(
        &self,
        original: &crate::data::batch::PyPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyPseudonymPseudonymizationBatchProof,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<crate::data::batch::PyPseudonymBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_pseudonym_rekey_batch(
        &self,
        original: &crate::data::batch::PyPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyPseudonymRekeyBatchProof,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyPseudonymBatch> {
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(crate::data::batch::PyPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    fn verify_pseudonym_rekey_batch(
        &self,
        original: &crate::data::batch::PyPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyPseudonymRekeyBatchProof,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyPseudonymBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_attribute_rekey_batch(
        &self,
        original: &crate::data::batch::PyAttributeBatch,
        proof: &crate::data::verifiable_batch::PyAttributeRekeyBatchProof,
        new_public_key: &crate::keys::PyAttributeSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyAttributeBatch> {
        let new_pk = libpep::keys::AttributeSessionPublicKey::from_point(new_public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(crate::data::batch::PyAttributeBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    fn verify_attribute_rekey_batch(
        &self,
        original: &crate::data::batch::PyAttributeBatch,
        proof: &crate::data::verifiable_batch::PyAttributeRekeyBatchProof,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyAttributeBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyAttributeBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_long_pseudonymization_batch(
        &self,
        original: &crate::data::batch::PyLongPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyLongPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<crate::data::batch::PyLongPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.inner)
            .map(crate::data::batch::PyLongPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verify_long_pseudonymization_batch(
        &self,
        original: &crate::data::batch::PyLongPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyLongPseudonymPseudonymizationBatchProof,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<crate::data::batch::PyLongPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.inner)
            .map(crate::data::batch::PyLongPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    fn verify_long_pseudonymization_batch(
        &self,
        original: &crate::data::batch::PyLongPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyLongPseudonymPseudonymizationBatchProof,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<crate::data::batch::PyLongPseudonymBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyLongPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_long_pseudonym_rekey_batch(
        &self,
        original: &crate::data::batch::PyLongPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyLongPseudonymRekeyBatchProof,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyLongPseudonymBatch> {
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(crate::data::batch::PyLongPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", any(feature = "elgamal3", not(feature = "batch-pk"))))]
    fn verify_long_pseudonym_rekey_batch(
        &self,
        original: &crate::data::batch::PyLongPseudonymBatch,
        proof: &crate::data::verifiable_batch::PyLongPseudonymRekeyBatchProof,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyLongPseudonymBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyLongPseudonymBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_long_attribute_rekey_batch(
        &self,
        original: &crate::data::batch::PyLongAttributeBatch,
        proof: &crate::data::verifiable_batch::PyLongAttributeRekeyBatchProof,
        new_public_key: &crate::keys::PyAttributeSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyLongAttributeBatch> {
        let new_pk = libpep::keys::AttributeSessionPublicKey::from_point(new_public_key.0 .0);
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(crate::data::batch::PyLongAttributeBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", any(feature = "elgamal3", not(feature = "batch-pk"))))]
    fn verify_long_attribute_rekey_batch(
        &self,
        original: &crate::data::batch::PyLongAttributeBatch,
        proof: &crate::data::verifiable_batch::PyLongAttributeRekeyBatchProof,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<crate::data::batch::PyLongAttributeBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyLongAttributeBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_record_transcryption_batch(
        &self,
        original: &crate::data::batch::PyRecordBatch,
        proof: &crate::data::verifiable_batch::PyRecordTranscryptionBatchProof,
        session_keys: &crate::keys::PySessionKeys,
        new_session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::batch::PyRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        let new_sk: libpep::keys::SessionKeys = new_session_keys.clone().into();
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.inner)
            .map(crate::data::batch::PyRecordBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verify_record_transcryption_batch(
        &self,
        original: &crate::data::batch::PyRecordBatch,
        proof: &crate::data::verifiable_batch::PyRecordTranscryptionBatchProof,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::batch::PyRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.inner)
            .map(crate::data::batch::PyRecordBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(feature = "elgamal3")]
    fn verify_record_transcryption_batch(
        &self,
        original: &crate::data::batch::PyRecordBatch,
        proof: &crate::data::verifiable_batch::PyRecordTranscryptionBatchProof,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::batch::PyRecordBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyRecordBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verify_long_record_transcryption_batch(
        &self,
        original: &crate::data::batch::PyLongRecordBatch,
        proof: &crate::data::verifiable_batch::PyLongRecordTranscryptionBatchProof,
        session_keys: &crate::keys::PySessionKeys,
        new_session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::batch::PyLongRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        let new_sk: libpep::keys::SessionKeys = new_session_keys.clone().into();
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.inner)
            .map(crate::data::batch::PyLongRecordBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verify_long_record_transcryption_batch(
        &self,
        original: &crate::data::batch::PyLongRecordBatch,
        proof: &crate::data::verifiable_batch::PyLongRecordTranscryptionBatchProof,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::batch::PyLongRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.inner)
            .map(crate::data::batch::PyLongRecordBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    fn verify_long_record_transcryption_batch(
        &self,
        original: &crate::data::batch::PyLongRecordBatch,
        proof: &crate::data::verifiable_batch::PyLongRecordTranscryptionBatchProof,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<crate::data::batch::PyLongRecordBatch> {
        proof
            .inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(crate::data::batch::PyLongRecordBatch::from)
            .ok_or_else(|| {
                crate::errors::verify_err_to_py(libpep::verifier::VerifyError::ProofRejected)
            })
    }
}

#[allow(dead_code)]
pub(crate) fn register_verifier_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifier>()?;
    Ok(())
}
