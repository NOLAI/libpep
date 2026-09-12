//! Python bindings for the verifiable batch flow.
//!
//! Wraps the eight batch-proof types from
//! [`libpep::data::verifiable`] (`PseudonymPseudonymizationBatchProof`,
//! `PseudonymRekeyBatchProof`, `AttributeRekeyBatchProof`, the three `Long*`
//! analogues, plus `RecordTranscryptionBatchProof` and
//! `LongRecordTranscryptionBatchProof`).
//!
//! Each Py wrapper carries an `inner: <Rust>` field, exposes
//! `to_json`/`from_json` (under `serde`), and a `verified_reconstruct_batch`
//! method that delegates to the underlying inherent impl. The cfg layout
//! mirrors the Rust one exactly:
//!   - `(batch-pk, !elgamal3)` — needs both the old `public_key` and the
//!     `new_public_key` (or `session_keys` / `new_session_keys` for records).
//!   - `(!batch-pk, !elgamal3)` — needs only the recipient `public_key` /
//!     `session_keys`.
//!   - `elgamal3` — no key parameter.
//!
//! This module also adds `verifiable_pseudonymize` / `verifiable_rekey` /
//! `verifiable_transcrypt` methods on the existing `Py*Batch` wrappers from
//! `data/py/batch.rs`. A second `#[pymethods]` block per `Py*Batch` is fine
//! because Cargo.toml enables PyO3's `multiple-pymethods` feature.

use crate::errors::{JsonFormatError, ProofRejectedError};
use pyo3::prelude::*;

#[cfg(feature = "serde")]
fn map_ser_err<E: std::fmt::Display>(e: E) -> PyErr {
    JsonFormatError::new_err(format!("Serialization failed: {}", e))
}

#[cfg(feature = "serde")]
fn map_de_err<E: std::fmt::Display>(e: E) -> PyErr {
    JsonFormatError::new_err(format!("Deserialization failed: {}", e))
}

fn map_verify_err() -> PyErr {
    ProofRejectedError::new_err("proof rejected")
}

use crate::data::batch::{PyAttributeBatch, PyPseudonymBatch, PyRecordBatch};
#[cfg(feature = "long")]
use crate::data::batch::{PyLongAttributeBatch, PyLongPseudonymBatch, PyLongRecordBatch};
use crate::factors::commitments::{
    PyVerifiablePseudonymizationCommitment, PyVerifiableRekeyCommitment,
    PyVerifiableTranscryptionCommitment,
};
use crate::factors::types::{
    PyAttributeRekeyInfo, PyPseudonymRekeyInfo, PyPseudonymizationInfo, PyTranscryptionInfo,
};
#[cfg(feature = "long")]
use libpep::data::verifiable::long::{
    LongAttributeRekeyBatchProof, LongPseudonymPseudonymizationBatchProof,
    LongPseudonymRekeyBatchProof,
};
#[cfg(feature = "long")]
use libpep::data::verifiable::records::LongRecordTranscryptionBatchProof;
use libpep::data::verifiable::records::RecordTranscryptionBatchProof;
use libpep::data::verifiable::simple::{
    AttributeRekeyBatchProof, PseudonymPseudonymizationBatchProof, PseudonymRekeyBatchProof,
};
use libpep::factors::{AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo};
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;

// ---------------------------------------------------------------------------
// PseudonymPseudonymizationBatchProof
// ---------------------------------------------------------------------------

#[pyclass(name = "PseudonymPseudonymizationBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyPseudonymPseudonymizationBatchProof {
    pub(crate) inner: PseudonymPseudonymizationBatchProof,
}

impl From<PseudonymPseudonymizationBatchProof> for PyPseudonymPseudonymizationBatchProof {
    fn from(inner: PseudonymPseudonymizationBatchProof) -> Self {
        Self { inner }
    }
}

impl From<PyPseudonymPseudonymizationBatchProof> for PseudonymPseudonymizationBatchProof {
    fn from(p: PyPseudonymPseudonymizationBatchProof) -> Self {
        p.inner
    }
}

#[pymethods]
impl PyPseudonymPseudonymizationBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<PseudonymPseudonymizationBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    /// Verify the proof against the original batch and the recipient public
    /// keys (under `batch-pk`, both the old and the new pk; under
    /// `!batch-pk`, only the recipient pk; under `elgamal3`, no pk),
    /// returning the reconstructed batch on success.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyPseudonymBatch,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.inner)
            .map(PyPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyPseudonymBatch,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.inner)
            .map(PyPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct_batch(
        &self,
        original: &PyPseudonymBatch,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyPseudonymBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// PseudonymRekeyBatchProof
// ---------------------------------------------------------------------------

#[pyclass(name = "PseudonymRekeyBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyPseudonymRekeyBatchProof {
    pub(crate) inner: PseudonymRekeyBatchProof,
}

impl From<PseudonymRekeyBatchProof> for PyPseudonymRekeyBatchProof {
    fn from(inner: PseudonymRekeyBatchProof) -> Self {
        Self { inner }
    }
}

impl From<PyPseudonymRekeyBatchProof> for PseudonymRekeyBatchProof {
    fn from(p: PyPseudonymRekeyBatchProof) -> Self {
        p.inner
    }
}

#[pymethods]
impl PyPseudonymRekeyBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<PseudonymRekeyBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyPseudonymBatch,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyPseudonymBatch> {
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(PyPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyPseudonymBatch,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyPseudonymBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// AttributeRekeyBatchProof
// ---------------------------------------------------------------------------

#[pyclass(name = "AttributeRekeyBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyAttributeRekeyBatchProof {
    pub(crate) inner: AttributeRekeyBatchProof,
}

impl From<AttributeRekeyBatchProof> for PyAttributeRekeyBatchProof {
    fn from(inner: AttributeRekeyBatchProof) -> Self {
        Self { inner }
    }
}

impl From<PyAttributeRekeyBatchProof> for AttributeRekeyBatchProof {
    fn from(p: PyAttributeRekeyBatchProof) -> Self {
        p.inner
    }
}

#[pymethods]
impl PyAttributeRekeyBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<AttributeRekeyBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyAttributeBatch,
        new_public_key: &crate::keys::PyAttributeSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyAttributeBatch> {
        let new_pk = libpep::keys::AttributeSessionPublicKey::from_point(new_public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(PyAttributeBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyAttributeBatch,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyAttributeBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyAttributeBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongPseudonymPseudonymizationBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[pyclass(name = "LongPseudonymPseudonymizationBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyLongPseudonymPseudonymizationBatchProof {
    pub(crate) inner: LongPseudonymPseudonymizationBatchProof,
}

#[cfg(feature = "long")]
impl From<LongPseudonymPseudonymizationBatchProof> for PyLongPseudonymPseudonymizationBatchProof {
    fn from(inner: LongPseudonymPseudonymizationBatchProof) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "long")]
impl From<PyLongPseudonymPseudonymizationBatchProof> for LongPseudonymPseudonymizationBatchProof {
    fn from(p: PyLongPseudonymPseudonymizationBatchProof) -> Self {
        p.inner
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongPseudonymPseudonymizationBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<LongPseudonymPseudonymizationBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongPseudonymBatch,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyLongPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.inner)
            .map(PyLongPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongPseudonymBatch,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyLongPseudonymBatch> {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.inner)
            .map(PyLongPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongPseudonymBatch,
        commitments: &PyVerifiablePseudonymizationCommitment,
    ) -> PyResult<PyLongPseudonymBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyLongPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongPseudonymRekeyBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[pyclass(name = "LongPseudonymRekeyBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyLongPseudonymRekeyBatchProof {
    pub(crate) inner: LongPseudonymRekeyBatchProof,
}

#[cfg(feature = "long")]
impl From<LongPseudonymRekeyBatchProof> for PyLongPseudonymRekeyBatchProof {
    fn from(inner: LongPseudonymRekeyBatchProof) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "long")]
impl From<PyLongPseudonymRekeyBatchProof> for LongPseudonymRekeyBatchProof {
    fn from(p: PyLongPseudonymRekeyBatchProof) -> Self {
        p.inner
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongPseudonymRekeyBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<LongPseudonymRekeyBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongPseudonymBatch,
        new_public_key: &crate::keys::PyPseudonymSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyLongPseudonymBatch> {
        let new_pk = libpep::keys::PseudonymSessionPublicKey::from_point(new_public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(PyLongPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongPseudonymBatch,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyLongPseudonymBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyLongPseudonymBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongAttributeRekeyBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[pyclass(name = "LongAttributeRekeyBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyLongAttributeRekeyBatchProof {
    pub(crate) inner: LongAttributeRekeyBatchProof,
}

#[cfg(feature = "long")]
impl From<LongAttributeRekeyBatchProof> for PyLongAttributeRekeyBatchProof {
    fn from(inner: LongAttributeRekeyBatchProof) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "long")]
impl From<PyLongAttributeRekeyBatchProof> for LongAttributeRekeyBatchProof {
    fn from(p: PyLongAttributeRekeyBatchProof) -> Self {
        p.inner
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongAttributeRekeyBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<LongAttributeRekeyBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongAttributeBatch,
        new_public_key: &crate::keys::PyAttributeSessionPublicKey,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyLongAttributeBatch> {
        let new_pk = libpep::keys::AttributeSessionPublicKey::from_point(new_public_key.0 .0);
        self.inner
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.inner)
            .map(PyLongAttributeBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongAttributeBatch,
        commitments: &PyVerifiableRekeyCommitment,
    ) -> PyResult<PyLongAttributeBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyLongAttributeBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// RecordTranscryptionBatchProof
// ---------------------------------------------------------------------------

#[pyclass(name = "RecordTranscryptionBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyRecordTranscryptionBatchProof {
    pub(crate) inner: RecordTranscryptionBatchProof,
}

impl From<RecordTranscryptionBatchProof> for PyRecordTranscryptionBatchProof {
    fn from(inner: RecordTranscryptionBatchProof) -> Self {
        Self { inner }
    }
}

impl From<PyRecordTranscryptionBatchProof> for RecordTranscryptionBatchProof {
    fn from(p: PyRecordTranscryptionBatchProof) -> Self {
        p.inner
    }
}

#[pymethods]
impl PyRecordTranscryptionBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<RecordTranscryptionBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyRecordBatch,
        session_keys: &crate::keys::PySessionKeys,
        new_session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        let new_sk: libpep::keys::SessionKeys = new_session_keys.clone().into();
        self.inner
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.inner)
            .map(PyRecordBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyRecordBatch,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.inner)
            .map(PyRecordBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct_batch(
        &self,
        original: &PyRecordBatch,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyRecordBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyRecordBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongRecordTranscryptionBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[pyclass(name = "LongRecordTranscryptionBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyLongRecordTranscryptionBatchProof {
    pub(crate) inner: LongRecordTranscryptionBatchProof,
}

#[cfg(feature = "long")]
impl From<LongRecordTranscryptionBatchProof> for PyLongRecordTranscryptionBatchProof {
    fn from(inner: LongRecordTranscryptionBatchProof) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "long")]
impl From<PyLongRecordTranscryptionBatchProof> for LongRecordTranscryptionBatchProof {
    fn from(p: PyLongRecordTranscryptionBatchProof) -> Self {
        p.inner
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongRecordTranscryptionBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<LongRecordTranscryptionBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongRecordBatch,
        session_keys: &crate::keys::PySessionKeys,
        new_session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyLongRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        let new_sk: libpep::keys::SessionKeys = new_session_keys.clone().into();
        self.inner
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.inner)
            .map(PyLongRecordBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongRecordBatch,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyLongRecordBatch> {
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.inner)
            .map(PyLongRecordBatch::from)
            .ok_or_else(map_verify_err)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct_batch(
        &self,
        original: &PyLongRecordBatch,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyLongRecordBatch> {
        self.inner
            .verified_reconstruct_batch(&original.inner, &commitments.inner)
            .map(PyLongRecordBatch::from)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// Producer methods on the existing Py*Batch types
//
// `pyo3` with `multiple-pymethods` enabled (see Cargo.toml) accepts a second
// `#[pymethods] impl PyType { ... }` block — these are merged with the
// primary block in `data/py/batch.rs`. We keep the verifiable-batch surface
// gated entirely behind this module so the non-verifiable build stays
// untouched.
// ---------------------------------------------------------------------------

#[pymethods]
impl PyPseudonymBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verifiable_pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
    ) -> PyPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner.verifiable_pseudonymize(&info, &mut rng).into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verifiable_pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .verifiable_pseudonymize(&info, &pk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
    ) -> PyPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner.verifiable_pseudonymize(&info, &mut rng).into()
    }

    fn verifiable_rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyPseudonymRekeyBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_rekey(&info.0, &mut rng).into()
    }
}

#[pymethods]
impl PyAttributeBatch {
    fn verifiable_rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyAttributeRekeyBatchProof {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.verifiable_rekey(&info, &mut rng).into()
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongPseudonymBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verifiable_pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
    ) -> PyLongPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner.verifiable_pseudonymize(&info, &mut rng).into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verifiable_pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyLongPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .verifiable_pseudonymize(&info, &pk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
    ) -> PyLongPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner.verifiable_pseudonymize(&info, &mut rng).into()
    }

    fn verifiable_rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyLongPseudonymRekeyBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_rekey(&info.0, &mut rng).into()
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongAttributeBatch {
    fn verifiable_rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyLongAttributeRekeyBatchProof {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.verifiable_rekey(&info, &mut rng).into()
    }
}

#[pymethods]
impl PyRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verifiable_transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
    ) -> PyRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner.verifiable_transcrypt(&info, &mut rng).into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verifiable_transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        session_keys: &crate::keys::PySessionKeys,
    ) -> PyRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .verifiable_transcrypt(&info, &sk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    fn verifiable_transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
    ) -> PyRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner.verifiable_transcrypt(&info, &mut rng).into()
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn verifiable_transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
    ) -> PyLongRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner.verifiable_transcrypt(&info, &mut rng).into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn verifiable_transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        session_keys: &crate::keys::PySessionKeys,
    ) -> PyLongRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let sk: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .verifiable_transcrypt(&info, &sk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    fn verifiable_transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
    ) -> PyLongRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner.verifiable_transcrypt(&info, &mut rng).into()
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymPseudonymizationBatchProof>()?;
    m.add_class::<PyPseudonymRekeyBatchProof>()?;
    m.add_class::<PyAttributeRekeyBatchProof>()?;
    m.add_class::<PyRecordTranscryptionBatchProof>()?;

    #[cfg(feature = "long")]
    {
        m.add_class::<PyLongPseudonymPseudonymizationBatchProof>()?;
        m.add_class::<PyLongPseudonymRekeyBatchProof>()?;
        m.add_class::<PyLongAttributeRekeyBatchProof>()?;
        m.add_class::<PyLongRecordTranscryptionBatchProof>()?;
    }

    Ok(())
}
