//! Python bindings for verifiable JSON transcryption.
//!
//! Wraps [`JSONTranscryptionProof`](crate::data::verifiable::json::JSONTranscryptionProof)
//! and [`VerifiableJSONBatch`](crate::data::verifiable::json::VerifiableJSONBatch),
//! and adds a `verifiable_transcrypt` producer on the existing
//! [`PyEncryptedPEPJSONValue`](crate::data::py::json::PyEncryptedPEPJSONValue).
//!
//! Verifier-side methods `verify_json_transcryption` / `verify_json_transcryption_batch`
//! are added to `PyVerifier` from this module via an extra `#[pymethods]` block
//! (PyO3's `multiple-pymethods` feature is enabled).

use crate::data::py::json::PyEncryptedPEPJSONValue;
use crate::data::verifiable::json::JSONTranscryptionProof;
#[cfg(all(feature = "batch", feature = "verifiable"))]
use crate::data::verifiable::json::VerifiableJSONBatch;
use crate::factors::py::commitments::PyVerifiableTranscryptionCommitment;
use crate::factors::py::contexts::PyTranscryptionInfo;
use crate::factors::TranscryptionInfo;
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
// JSONTranscryptionProof
// ---------------------------------------------------------------------------

/// Proof for verifiable transcryption of an `EncryptedPEPJSONValue`.
#[pyclass(name = "JSONTranscryptionProof", from_py_object)]
#[derive(Clone)]
pub struct PyJSONTranscryptionProof {
    pub(crate) inner: JSONTranscryptionProof,
}

impl From<JSONTranscryptionProof> for PyJSONTranscryptionProof {
    fn from(inner: JSONTranscryptionProof) -> Self {
        Self { inner }
    }
}

impl From<PyJSONTranscryptionProof> for JSONTranscryptionProof {
    fn from(p: PyJSONTranscryptionProof) -> Self {
        p.inner
    }
}

#[pymethods]
impl PyJSONTranscryptionProof {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<JSONTranscryptionProof>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }

    /// Verify the proof against the original encrypted JSON value and the
    /// published transition commitments. Returns `True` on success.
    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &PyEncryptedPEPJSONValue,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> bool {
        self.inner.verify(&original.0, &commitments.inner)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &PyEncryptedPEPJSONValue,
        session_keys: &crate::keys::py::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> bool {
        let keys: crate::keys::SessionKeys = session_keys.clone().into();
        self.inner.verify(&original.0, &keys, &commitments.inner)
    }

    /// Verify and reconstruct the transcrypted JSON value.
    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &PyEncryptedPEPJSONValue,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPEPJSONValue> {
        self.inner
            .verified_reconstruct(&original.0, &commitments.inner)
            .map(PyEncryptedPEPJSONValue)
            .ok_or_else(map_verify_err)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &PyEncryptedPEPJSONValue,
        session_keys: &crate::keys::py::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPEPJSONValue> {
        let keys: crate::keys::SessionKeys = session_keys.clone().into();
        self.inner
            .verified_reconstruct(&original.0, &keys, &commitments.inner)
            .map(PyEncryptedPEPJSONValue)
            .ok_or_else(map_verify_err)
    }
}

// ---------------------------------------------------------------------------
// VerifiableJSONBatch
// ---------------------------------------------------------------------------

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[pyclass(name = "VerifiableJSONBatch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableJSONBatch {
    pub(crate) inner: VerifiableJSONBatch,
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<VerifiableJSONBatch> for PyVerifiableJSONBatch {
    fn from(inner: VerifiableJSONBatch) -> Self {
        Self { inner }
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<PyVerifiableJSONBatch> for VerifiableJSONBatch {
    fn from(b: PyVerifiableJSONBatch) -> Self {
        b.inner
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[pymethods]
impl PyVerifiableJSONBatch {
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(map_ser_err)
    }

    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<VerifiableJSONBatch>(json)
            .map(|inner| Self { inner })
            .map_err(map_de_err)
    }
}

// ---------------------------------------------------------------------------
// Producer: PyEncryptedPEPJSONValue.verifiable_transcrypt
// ---------------------------------------------------------------------------

#[pymethods]
impl PyEncryptedPEPJSONValue {
    /// Produce a verifiable transcryption proof for this encrypted JSON
    /// value. The transcryption itself is folded into the proof; pass the
    /// proof together with the original ciphertext to a verifier to obtain
    /// the reconstructed value.
    #[cfg(feature = "elgamal3")]
    #[pyo3(name = "verifiable_transcrypt")]
    fn py_verifiable_transcrypt(&self, info: &PyTranscryptionInfo) -> PyJSONTranscryptionProof {
        use crate::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        PyJSONTranscryptionProof {
            inner: self.0.verifiable_transcrypt(&info, &mut rng),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    #[pyo3(name = "verifiable_transcrypt")]
    fn py_verifiable_transcrypt(
        &self,
        info: &PyTranscryptionInfo,
        session_keys: &crate::keys::py::PySessionKeys,
    ) -> PyJSONTranscryptionProof {
        use crate::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(info);
        let keys: crate::keys::SessionKeys = session_keys.clone().into();
        PyJSONTranscryptionProof {
            inner: self.0.verifiable_transcrypt(&info, &keys, &mut rng),
        }
    }
}

// ---------------------------------------------------------------------------
// Verifier methods: verify_json_transcryption(_batch)
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::verifier::py::PyVerifier {
    /// Verify a JSON transcryption proof, returning the reconstructed
    /// encrypted JSON value on success.
    #[cfg(feature = "elgamal3")]
    fn verify_json_transcryption(
        &self,
        original: &PyEncryptedPEPJSONValue,
        proof: &PyJSONTranscryptionProof,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPEPJSONValue> {
        self.verified_reconstruct_transcryption(&original.0, &proof.inner, &commitments.inner)
            .map(PyEncryptedPEPJSONValue)
            .map_err(PyErr::from)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify_json_transcryption(
        &self,
        original: &PyEncryptedPEPJSONValue,
        proof: &PyJSONTranscryptionProof,
        session_keys: &crate::keys::py::PySessionKeys,
        commitments: &PyVerifiableTranscryptionCommitment,
    ) -> PyResult<PyEncryptedPEPJSONValue> {
        let keys: crate::keys::SessionKeys = session_keys.clone().into();
        self.verified_reconstruct_transcryption(
            &original.0,
            &proof.inner,
            &keys,
            &commitments.inner,
        )
        .map(PyEncryptedPEPJSONValue)
        .map_err(PyErr::from)
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyJSONTranscryptionProof>()?;
    #[cfg(all(feature = "batch", feature = "verifiable"))]
    m.add_class::<PyVerifiableJSONBatch>()?;
    Ok(())
}
