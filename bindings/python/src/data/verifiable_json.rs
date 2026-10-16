//! Python bindings for verifiable JSON transcryption.
//!
//! Wraps [`JsonTranscryptionProof`] and [`JsonTranscryptionBatchProof`], and adds a
//! `verifiable_transcrypt` producer on the existing
//! [`PyEncryptedPepJsonValue`].
//!
//! Verifier-side methods `verify_json_transcryption` / `verify_json_transcryption_batch`
//! are added to `PyVerifier` from this module via an extra `#[pymethods]` block
//! (PyO3's `multiple-pymethods` feature is enabled).

use crate::data::json::PyEncryptedPepJsonValue;
use crate::factors::commitments::PyVerifiableTranscryptionCommitment;
use crate::factors::types::PyTranscryptionInfo;
#[cfg(all(feature = "batch", feature = "verifiable"))]
use libpep::data::verifiable::json::JsonTranscryptionBatchProof;
use libpep::data::verifiable::json::JsonTranscryptionProof;
use libpep::data::verifiable::traits::VerifiableTranscryptionProof;
use libpep::factors::TranscryptionInfo;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[cfg(feature = "serde")]
fn map_ser_err<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(format!("Serialization failed: {}", e))
}

#[cfg(feature = "serde")]
fn map_de_err<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(format!("Deserialization failed: {}", e))
}

fn map_verify_err() -> PyErr {
    PyValueError::new_err("verification failed")
}

// ---------------------------------------------------------------------------
// JsonTranscryptionProof
// ---------------------------------------------------------------------------

/// Proof for verifiable transcryption of an `EncryptedPepJsonValue`.
#[pyclass(name = "JsonTranscryptionProof", from_py_object)]
#[derive(Clone)]
pub struct PyJsonTranscryptionProof {
    pub(crate) inner: JsonTranscryptionProof,
}

impl From<JsonTranscryptionProof> for PyJsonTranscryptionProof {
    fn from(inner: JsonTranscryptionProof) -> Self {
        Self { inner }
    }
}

impl From<PyJsonTranscryptionProof> for JsonTranscryptionProof {
    fn from(p: PyJsonTranscryptionProof) -> Self {
        p.inner
    }
}

#[pymethods]
impl PyJsonTranscryptionProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<JsonTranscryptionProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    /// Verify the proof against the original encrypted JSON value and the
    /// published transition commitments. Returns `True` on success.
    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &PyEncryptedPepJsonValue,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> bool {
        self.inner.verify(&original.0, &commitments.inner)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &PyEncryptedPepJsonValue,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> bool {
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .verify(&original.0, &keys.public(), &commitments.inner)
    }

    /// Verify and reconstruct the transcrypted JSON value.
    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &PyEncryptedPepJsonValue,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPepJsonValue> {
        self.inner
            .verified_reconstruct(&original.0, &commitments.inner)
            .map(PyEncryptedPepJsonValue)
            .ok_or_else(map_verify_err)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &PyEncryptedPepJsonValue,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPepJsonValue> {
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .verified_reconstruct(&original.0, &keys.public(), &commitments.inner)
            .map(PyEncryptedPepJsonValue)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// JsonTranscryptionBatchProof
// ---------------------------------------------------------------------------

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[pyclass(name = "JsonTranscryptionBatchProof", from_py_object)]
#[derive(Clone)]
pub struct PyJsonTranscryptionBatchProof {
    pub(crate) inner: JsonTranscryptionBatchProof,
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<JsonTranscryptionBatchProof> for PyJsonTranscryptionBatchProof {
    fn from(inner: JsonTranscryptionBatchProof) -> Self {
        Self { inner }
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<PyJsonTranscryptionBatchProof> for JsonTranscryptionBatchProof {
    fn from(b: PyJsonTranscryptionBatchProof) -> Self {
        b.inner
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[pymethods]
impl PyJsonTranscryptionBatchProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<JsonTranscryptionBatchProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }
}

// ---------------------------------------------------------------------------
// Producer: PyEncryptedPepJsonValue.verifiable_transcrypt
// ---------------------------------------------------------------------------

#[pymethods]
impl PyEncryptedPepJsonValue {
    /// Produce a verifiable transcryption proof for this encrypted JSON
    /// value. The transcryption itself is folded into the proof; pass the
    /// proof together with the original ciphertext to a verifier to obtain
    /// the reconstructed value.
    #[cfg(feature = "elgamal3")]
    #[pyo3(name = "verifiable_transcrypt")]
    fn py_verifiable_transcrypt(&self, info: &PyTranscryptionInfo) -> PyJsonTranscryptionProof {
        use libpep::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        PyJsonTranscryptionProof {
            inner: self.0.verifiable_transcrypt(&info, &mut rng),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    #[pyo3(name = "verifiable_transcrypt")]
    fn py_verifiable_transcrypt(
        &self,
        info: &PyTranscryptionInfo,
        session_keys: &crate::keys::PySessionKeys,
    ) -> PyJsonTranscryptionProof {
        use libpep::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        PyJsonTranscryptionProof {
            inner: self
                .0
                .verifiable_transcrypt(&info, &keys.public(), &mut rng),
        }
    }
}

// ---------------------------------------------------------------------------
// Verifier methods: verify_json_transcryption(_batch)
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::verifier::PyVerifier {
    /// Verify a JSON transcryption proof, returning the reconstructed
    /// encrypted JSON value on success.
    #[cfg(feature = "elgamal3")]
    fn verify_json_transcryption(
        &self,
        original: &PyEncryptedPepJsonValue,
        proof: &PyJsonTranscryptionProof,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPepJsonValue> {
        self.verified_reconstruct_transcryption(&original.0, &proof.inner, &commitments.inner)
            .map(PyEncryptedPepJsonValue)
            .map_err(crate::errors::verify_err_to_py)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify_json_transcryption(
        &self,
        original: &PyEncryptedPepJsonValue,
        proof: &PyJsonTranscryptionProof,
        session_keys: &crate::keys::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPepJsonValue> {
        let keys: libpep::keys::SessionKeys = session_keys.clone().into();
        self.verified_reconstruct_transcryption(
            &original.0,
            &proof.inner,
            &keys.public(),
            &commitments.inner,
        )
        .map(PyEncryptedPepJsonValue)
        .map_err(crate::errors::verify_err_to_py)
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyJsonTranscryptionProof>()?;
    #[cfg(all(feature = "batch", feature = "verifiable"))]
    m.add_class::<PyJsonTranscryptionBatchProof>()?;
    Ok(())
}
