//! Python bindings for [`EncryptedBatch`] as concrete `#[pyclass]` wrappers.
//!
//! `EncryptedBatch<E>` is generic so it can't itself be exposed as a
//! `#[pyclass]`. Instead this module defines one wrapper per concrete `E`
//! that occurs in batch ops (simple/long pseudonyms and attributes, records).
//! Each wrapper mirrors the Rust API 1:1 so callers can hold a batch across
//! method calls instead of flattening to a `Vec<E>` between every step.
//!
//! The cfg forks here mirror the Rust impl in `transcryptor::batch`:
//!   - `(batch-pk, !elgamal3)` — the recipient public key is carried by the
//!     batch and converted in lockstep on each op.
//!   - `(!batch-pk, !elgamal3)` — constructor takes only items; ops take an
//!     extra `public_key` parameter.
//!   - `elgamal3` — every ciphertext already carries its own `gy`, so neither
//!     the constructor nor the ops need a public key.

#[cfg(feature = "long")]
use crate::data::long::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::data::records::PyEncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::PyLongEncryptedRecord;
use crate::data::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::types::{
    PyAttributeRekeyInfo, PyPseudonymRekeyInfo, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use libpep::data::batch::EncryptedBatch;
use libpep::data::long::LongEncryptedAttribute;
use libpep::data::long::LongEncryptedPseudonym;
use libpep::data::records::EncryptedRecord;
use libpep::data::records::LongEncryptedRecord;
use libpep::data::simple::EncryptedAttribute;
use libpep::data::simple::EncryptedPseudonym;
use libpep::factors::{AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo};
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;
use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `BatchError` into the matching typed Python exception.
#[inline]
fn map_batch_err(e: libpep::errors::BatchError) -> PyErr {
    crate::errors::batch_err_to_py(e)
}

// ---------------------------------------------------------------------------
// PyPseudonymBatch  --  EncryptedBatch<EncryptedPseudonym>
// ---------------------------------------------------------------------------

/// A batch of `EncryptedPseudonym`s sharing a recipient session.
#[pyclass(name = "EncryptedPseudonymBatch", from_py_object)]
#[derive(Clone)]
pub struct PyPseudonymBatch {
    pub(crate) inner: EncryptedBatch<EncryptedPseudonym>,
}

impl From<EncryptedBatch<EncryptedPseudonym>> for PyPseudonymBatch {
    fn from(inner: EncryptedBatch<EncryptedPseudonym>) -> Self {
        Self { inner }
    }
}

impl From<PyPseudonymBatch> for EncryptedBatch<EncryptedPseudonym> {
    fn from(b: PyPseudonymBatch) -> Self {
        b.inner
    }
}

#[pymethods]
impl PyPseudonymBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[new]
    fn new(
        items: Vec<PyEncryptedPseudonym>,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyResult<Self> {
        let items: Vec<EncryptedPseudonym> = items.into_iter().map(|p| p.0).collect();
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        EncryptedBatch::new(items, pk)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[new]
    fn new(items: Vec<PyEncryptedPseudonym>) -> PyResult<Self> {
        let items: Vec<EncryptedPseudonym> = items.into_iter().map(|p| p.0).collect();
        EncryptedBatch::new(items)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    /// Number of items in the batch.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Number of items in the batch.
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the batch is empty.
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clone the items out of the batch.
    fn items(&self) -> Vec<PyEncryptedPseudonym> {
        self.inner
            .as_items()
            .iter()
            .map(|e| PyEncryptedPseudonym(*e))
            .collect()
    }

    /// The recipient public key carried by this batch (only under
    /// `(batch-pk, !elgamal3)`).
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn public_key(&self) -> crate::keys::PyPseudonymSessionPublicKey {
        crate::keys::PyPseudonymSessionPublicKey(
            crate::elgamal::arithmetic::group_elements::PyGroupElement(
                *libpep::keys::PublicKey::value(&self.inner.public_key),
            ),
        )
    }

    /// Pseudonymize every item in the batch (shuffles).
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn pseudonymize(&mut self, info: &PyPseudonymizationInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner
            .pseudonymize(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .pseudonymize(&info, &pk, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn pseudonymize(&mut self, info: &PyPseudonymizationInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner
            .pseudonymize(&info, &mut rng)
            .map_err(map_batch_err)
    }

    /// Rekey every item in the batch (shuffles).
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        self.inner.rekey(&info.0, &mut rng).map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        self.inner.rekey(&info.0, &mut rng).map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        self.inner.rekey(&info.0, &mut rng).map_err(map_batch_err)
    }

    /// Transcrypt every item in the batch (shuffles).
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .transcrypt(&info, &pk, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }
}

// ---------------------------------------------------------------------------
// PyAttributeBatch  --  EncryptedBatch<EncryptedAttribute>
// ---------------------------------------------------------------------------

/// A batch of `EncryptedAttribute`s sharing a recipient session.
#[pyclass(name = "EncryptedAttributeBatch", from_py_object)]
#[derive(Clone)]
pub struct PyAttributeBatch {
    pub(crate) inner: EncryptedBatch<EncryptedAttribute>,
}

impl From<EncryptedBatch<EncryptedAttribute>> for PyAttributeBatch {
    fn from(inner: EncryptedBatch<EncryptedAttribute>) -> Self {
        Self { inner }
    }
}

impl From<PyAttributeBatch> for EncryptedBatch<EncryptedAttribute> {
    fn from(b: PyAttributeBatch) -> Self {
        b.inner
    }
}

#[pymethods]
impl PyAttributeBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[new]
    fn new(
        items: Vec<PyEncryptedAttribute>,
        public_key: &crate::keys::PyAttributeSessionPublicKey,
    ) -> PyResult<Self> {
        let items: Vec<EncryptedAttribute> = items.into_iter().map(|a| a.0).collect();
        let pk = libpep::keys::AttributeSessionPublicKey::from_point(public_key.0 .0);
        EncryptedBatch::new(items, pk)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[new]
    fn new(items: Vec<PyEncryptedAttribute>) -> PyResult<Self> {
        let items: Vec<EncryptedAttribute> = items.into_iter().map(|a| a.0).collect();
        EncryptedBatch::new(items)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn items(&self) -> Vec<PyEncryptedAttribute> {
        self.inner
            .as_items()
            .iter()
            .map(|e| PyEncryptedAttribute(*e))
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn public_key(&self) -> crate::keys::PyAttributeSessionPublicKey {
        crate::keys::PyAttributeSessionPublicKey(
            crate::elgamal::arithmetic::group_elements::PyGroupElement(
                *libpep::keys::PublicKey::value(&self.inner.public_key),
            ),
        )
    }

    // No `pseudonymize` for attribute batches (mirroring the Rust impl).

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.rekey(&info, &mut rng).map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.rekey(&info, &mut rng).map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.rekey(&info, &mut rng).map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        public_key: &crate::keys::PyAttributeSessionPublicKey,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let pk = libpep::keys::AttributeSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .transcrypt(&info, &pk, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }
}

// ---------------------------------------------------------------------------
// PyLongPseudonymBatch  --  EncryptedBatch<LongEncryptedPseudonym>
// ---------------------------------------------------------------------------

/// A batch of `LongEncryptedPseudonym`s sharing a recipient session.
#[cfg(feature = "long")]
#[pyclass(name = "LongEncryptedPseudonymBatch", from_py_object)]
#[derive(Clone)]
pub struct PyLongPseudonymBatch {
    pub(crate) inner: EncryptedBatch<LongEncryptedPseudonym>,
}

#[cfg(feature = "long")]
impl From<EncryptedBatch<LongEncryptedPseudonym>> for PyLongPseudonymBatch {
    fn from(inner: EncryptedBatch<LongEncryptedPseudonym>) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "long")]
impl From<PyLongPseudonymBatch> for EncryptedBatch<LongEncryptedPseudonym> {
    fn from(b: PyLongPseudonymBatch) -> Self {
        b.inner
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongPseudonymBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[new]
    fn new(
        items: Vec<PyLongEncryptedPseudonym>,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyResult<Self> {
        let items: Vec<LongEncryptedPseudonym> = items.into_iter().map(|p| p.0).collect();
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        EncryptedBatch::new(items, pk)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[new]
    fn new(items: Vec<PyLongEncryptedPseudonym>) -> PyResult<Self> {
        let items: Vec<LongEncryptedPseudonym> = items.into_iter().map(|p| p.0).collect();
        EncryptedBatch::new(items)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn items(&self) -> Vec<PyLongEncryptedPseudonym> {
        self.inner
            .as_items()
            .iter()
            .map(|e| PyLongEncryptedPseudonym(e.clone()))
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn public_key(&self) -> crate::keys::PyPseudonymSessionPublicKey {
        crate::keys::PyPseudonymSessionPublicKey(
            crate::elgamal::arithmetic::group_elements::PyGroupElement(
                *libpep::keys::PublicKey::value(&self.inner.public_key),
            ),
        )
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn pseudonymize(&mut self, info: &PyPseudonymizationInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner
            .pseudonymize(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn pseudonymize(
        &mut self,
        info: &PyPseudonymizationInfo,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .pseudonymize(&info, &pk, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn pseudonymize(&mut self, info: &PyPseudonymizationInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(info);
        self.inner
            .pseudonymize(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        self.inner.rekey(&info.0, &mut rng).map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        self.inner.rekey(&info.0, &mut rng).map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn rekey(&mut self, info: &PyPseudonymRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        self.inner.rekey(&info.0, &mut rng).map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        public_key: &crate::keys::PyPseudonymSessionPublicKey,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .transcrypt(&info, &pk, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }
}

// ---------------------------------------------------------------------------
// PyLongAttributeBatch  --  EncryptedBatch<LongEncryptedAttribute>
// ---------------------------------------------------------------------------

/// A batch of `LongEncryptedAttribute`s sharing a recipient session.
#[cfg(feature = "long")]
#[pyclass(name = "LongEncryptedAttributeBatch", from_py_object)]
#[derive(Clone)]
pub struct PyLongAttributeBatch {
    pub(crate) inner: EncryptedBatch<LongEncryptedAttribute>,
}

#[cfg(feature = "long")]
impl From<EncryptedBatch<LongEncryptedAttribute>> for PyLongAttributeBatch {
    fn from(inner: EncryptedBatch<LongEncryptedAttribute>) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "long")]
impl From<PyLongAttributeBatch> for EncryptedBatch<LongEncryptedAttribute> {
    fn from(b: PyLongAttributeBatch) -> Self {
        b.inner
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongAttributeBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[new]
    fn new(
        items: Vec<PyLongEncryptedAttribute>,
        public_key: &crate::keys::PyAttributeSessionPublicKey,
    ) -> PyResult<Self> {
        let items: Vec<LongEncryptedAttribute> = items.into_iter().map(|a| a.0).collect();
        let pk = libpep::keys::AttributeSessionPublicKey::from_point(public_key.0 .0);
        EncryptedBatch::new(items, pk)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[new]
    fn new(items: Vec<PyLongEncryptedAttribute>) -> PyResult<Self> {
        let items: Vec<LongEncryptedAttribute> = items.into_iter().map(|a| a.0).collect();
        EncryptedBatch::new(items)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn items(&self) -> Vec<PyLongEncryptedAttribute> {
        self.inner
            .as_items()
            .iter()
            .map(|e| PyLongEncryptedAttribute(e.clone()))
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn public_key(&self) -> crate::keys::PyAttributeSessionPublicKey {
        crate::keys::PyAttributeSessionPublicKey(
            crate::elgamal::arithmetic::group_elements::PyGroupElement(
                *libpep::keys::PublicKey::value(&self.inner.public_key),
            ),
        )
    }

    // No `pseudonymize` for long-attribute batches (mirroring the Rust impl).

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.rekey(&info, &mut rng).map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.rekey(&info, &mut rng).map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn rekey(&mut self, info: &PyAttributeRekeyInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(info);
        self.inner.rekey(&info, &mut rng).map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        public_key: &crate::keys::PyAttributeSessionPublicKey,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let pk = libpep::keys::AttributeSessionPublicKey::from_point(public_key.0 .0);
        self.inner
            .transcrypt(&info, &pk, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }
}

// ---------------------------------------------------------------------------
// PyRecordBatch  --  EncryptedBatch<EncryptedRecord>
// ---------------------------------------------------------------------------

/// A batch of `EncryptedRecord`s sharing a recipient session-key bundle.
#[pyclass(name = "EncryptedRecordBatch", from_py_object)]
#[derive(Clone)]
pub struct PyRecordBatch {
    pub(crate) inner: EncryptedBatch<EncryptedRecord>,
}

impl From<EncryptedBatch<EncryptedRecord>> for PyRecordBatch {
    fn from(inner: EncryptedBatch<EncryptedRecord>) -> Self {
        Self { inner }
    }
}

impl From<PyRecordBatch> for EncryptedBatch<EncryptedRecord> {
    fn from(b: PyRecordBatch) -> Self {
        b.inner
    }
}

#[pymethods]
impl PyRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[new]
    fn new(
        items: Vec<PyEncryptedRecord>,
        session_keys: &crate::keys::PySessionKeys,
    ) -> PyResult<Self> {
        let items: Vec<EncryptedRecord> = items.into_iter().map(|r| r.0).collect();
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        EncryptedBatch::new(items, keys)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[new]
    fn new(items: Vec<PyEncryptedRecord>) -> PyResult<Self> {
        let items: Vec<EncryptedRecord> = items.into_iter().map(|r| r.0).collect();
        EncryptedBatch::new(items)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn items(&self) -> Vec<PyEncryptedRecord> {
        self.inner
            .as_items()
            .iter()
            .map(|e| PyEncryptedRecord(e.clone()))
            .collect()
    }

    /// The session key bundle carried by this batch (only under
    /// `(batch-pk, !elgamal3)`).
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn public_key(&self) -> crate::keys::PySessionKeys {
        rust_session_keys_to_py(&self.inner.public_key)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        session_keys: &crate::keys::PySessionKeys,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .transcrypt(&info, &keys, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }
}

// ---------------------------------------------------------------------------
// PyLongRecordBatch  --  EncryptedBatch<LongEncryptedRecord>
// ---------------------------------------------------------------------------

/// A batch of `LongEncryptedRecord`s sharing a recipient session-key bundle.
#[cfg(feature = "long")]
#[pyclass(name = "LongEncryptedRecordBatch", from_py_object)]
#[derive(Clone)]
pub struct PyLongRecordBatch {
    pub(crate) inner: EncryptedBatch<LongEncryptedRecord>,
}

#[cfg(feature = "long")]
impl From<EncryptedBatch<LongEncryptedRecord>> for PyLongRecordBatch {
    fn from(inner: EncryptedBatch<LongEncryptedRecord>) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "long")]
impl From<PyLongRecordBatch> for EncryptedBatch<LongEncryptedRecord> {
    fn from(b: PyLongRecordBatch) -> Self {
        b.inner
    }
}

#[cfg(feature = "long")]
#[pymethods]
impl PyLongRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[new]
    fn new(
        items: Vec<PyLongEncryptedRecord>,
        session_keys: &crate::keys::PySessionKeys,
    ) -> PyResult<Self> {
        let items: Vec<LongEncryptedRecord> = items.into_iter().map(|r| r.0).collect();
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        EncryptedBatch::new(items, keys)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[new]
    fn new(items: Vec<PyLongEncryptedRecord>) -> PyResult<Self> {
        let items: Vec<LongEncryptedRecord> = items.into_iter().map(|r| r.0).collect();
        EncryptedBatch::new(items)
            .map(|inner| Self { inner })
            .map_err(map_batch_err)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn items(&self) -> Vec<PyLongEncryptedRecord> {
        self.inner
            .as_items()
            .iter()
            .map(|e| PyLongEncryptedRecord(e.clone()))
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn public_key(&self) -> crate::keys::PySessionKeys {
        rust_session_keys_to_py(&self.inner.public_key)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    fn transcrypt(
        &mut self,
        info: &PyTranscryptionInfo,
        session_keys: &crate::keys::PySessionKeys,
    ) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .transcrypt(&info, &keys, &mut rng)
            .map_err(map_batch_err)
    }

    #[cfg(feature = "elgamal3")]
    fn transcrypt(&mut self, info: &PyTranscryptionInfo) -> PyResult<()> {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        self.inner
            .transcrypt(&info, &mut rng)
            .map_err(map_batch_err)
    }
}

// ---------------------------------------------------------------------------
// Helper: convert Rust `SessionKeys` back into the Python wrapper struct.
// Only needed for the `public_key()` getter on record batches, which exists
// solely under `(batch-pk, !elgamal3)`.
// ---------------------------------------------------------------------------

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
fn rust_session_keys_to_py(keys: &libpep::keys::SessionKeys) -> crate::keys::PySessionKeys {
    use crate::elgamal::arithmetic::group_elements::PyGroupElement;
    use crate::elgamal::arithmetic::scalars::PyScalarNonZero;
    use crate::keys::types::{
        PyAttributeSessionKeys, PyAttributeSessionPublicKey, PyAttributeSessionSecretKey,
        PyPseudonymSessionKeys, PyPseudonymSessionPublicKey, PyPseudonymSessionSecretKey,
    };

    crate::keys::PySessionKeys {
        pseudonym: PyPseudonymSessionKeys {
            public: PyPseudonymSessionPublicKey(PyGroupElement(*libpep::keys::PublicKey::value(
                &keys.pseudonym.public,
            ))),
            secret: PyPseudonymSessionSecretKey(PyScalarNonZero(*libpep::keys::SecretKey::value(
                &keys.pseudonym.secret,
            ))),
        },
        attribute: PyAttributeSessionKeys {
            public: PyAttributeSessionPublicKey(PyGroupElement(*libpep::keys::PublicKey::value(
                &keys.attribute.public,
            ))),
            secret: PyAttributeSessionSecretKey(PyScalarNonZero(*libpep::keys::SecretKey::value(
                &keys.attribute.secret,
            ))),
        },
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymBatch>()?;
    m.add_class::<PyAttributeBatch>()?;
    m.add_class::<PyRecordBatch>()?;

    #[cfg(feature = "long")]
    {
        m.add_class::<PyLongPseudonymBatch>()?;
        m.add_class::<PyLongAttributeBatch>()?;
        m.add_class::<PyLongRecordBatch>()?;
    }

    Ok(())
}
