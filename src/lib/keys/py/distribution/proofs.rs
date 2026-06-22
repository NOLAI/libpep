//! Python bindings for session-key-share zero-knowledge proofs.
//!
//! These bindings are part of the `verifiable-derivation` surface: the
//! underlying Rust types live under `crate::keys::distribution::proofs` and
//! are only available with `feature = "verifiable"`.

#![cfg(feature = "verifiable-derivation")]

use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::arithmetic::py::scalars::PyScalarNonZero;
use crate::keys::distribution::{BlindingCommitment, BlindingCommitments, SessionKeyShareProof};
use pyo3::prelude::*;

#[cfg(feature = "serde")]
use pyo3::exceptions::PyValueError;

/// Public commitment `B_i = b_i · G` to a per-transcryptor blinding factor.
#[pyclass(name = "BlindingCommitment", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyBlindingCommitment {
    pub(crate) inner: BlindingCommitment,
}

#[pymethods]
impl PyBlindingCommitment {
    /// Create a blinding commitment from a blinding scalar.
    #[new]
    fn new(blinding: PyScalarNonZero) -> Self {
        Self {
            inner: BlindingCommitment::new(&blinding.0),
        }
    }

    /// Construct directly from an existing group element (`B_i`).
    #[staticmethod]
    fn from_point(point: PyGroupElement) -> Self {
        Self {
            inner: BlindingCommitment(point.0),
        }
    }

    /// Get the commitment value as a group element.
    #[pyo3(name = "value")]
    fn value(&self) -> PyGroupElement {
        PyGroupElement(*self.inner.value())
    }

    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<BlindingCommitment> for PyBlindingCommitment {
    fn from(inner: BlindingCommitment) -> Self {
        Self { inner }
    }
}

impl From<PyBlindingCommitment> for BlindingCommitment {
    fn from(py: PyBlindingCommitment) -> Self {
        py.inner
    }
}

/// Pair of blinding commitments for one transcryptor (pseudonym + attribute).
#[pyclass(name = "BlindingCommitments", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyBlindingCommitments {
    pub(crate) inner: BlindingCommitments,
}

#[pymethods]
impl PyBlindingCommitments {
    /// Create blinding commitments from pseudonym and attribute blinding scalars.
    #[new]
    fn new(pseudonym_blinding: PyScalarNonZero, attribute_blinding: PyScalarNonZero) -> Self {
        Self {
            inner: BlindingCommitments::new(&pseudonym_blinding.0, &attribute_blinding.0),
        }
    }

    /// Build directly from two preconstructed commitments.
    #[staticmethod]
    fn from_commitments(pseudonym: PyBlindingCommitment, attribute: PyBlindingCommitment) -> Self {
        Self {
            inner: BlindingCommitments {
                pseudonym: pseudonym.inner,
                attribute: attribute.inner,
            },
        }
    }

    #[getter]
    fn pseudonym(&self) -> PyBlindingCommitment {
        PyBlindingCommitment {
            inner: self.inner.pseudonym,
        }
    }

    #[getter]
    fn attribute(&self) -> PyBlindingCommitment {
        PyBlindingCommitment {
            inner: self.inner.attribute,
        }
    }

    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<BlindingCommitments> for PyBlindingCommitments {
    fn from(inner: BlindingCommitments) -> Self {
        Self { inner }
    }
}

impl From<PyBlindingCommitments> for BlindingCommitments {
    fn from(py: PyBlindingCommitments) -> Self {
        py.inner
    }
}

/// Zero-knowledge proof that a session-key share `u_i = b_i · k_i` was
/// correctly constructed.
#[pyclass(name = "SessionKeyShareProof", from_py_object)]
#[derive(Clone, Copy)]
pub struct PySessionKeyShareProof {
    pub(crate) inner: SessionKeyShareProof,
}

#[pymethods]
impl PySessionKeyShareProof {
    /// Create a session-key-share proof.
    ///
    /// Args:
    ///     blinding: The secret blinding scalar `b_i`.
    ///     rekey_commitment: The public commitment `K_i = k_i · G`.
    #[new]
    fn new(blinding: PyScalarNonZero, rekey_commitment: PyGroupElement) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: SessionKeyShareProof::new(&blinding.0, &rekey_commitment.0, &mut rng),
        }
    }

    /// Verify the proof against a blinding commitment and rekey commitment.
    fn verify(
        &self,
        blinding_commitment: &PyBlindingCommitment,
        rekey_commitment: PyGroupElement,
    ) -> bool {
        self.inner
            .verify(&blinding_commitment.inner, &rekey_commitment.0)
    }

    /// Return the public commitment `U_i = u_i · G` to the session-key share.
    fn share_commitment(&self) -> PyGroupElement {
        PyGroupElement(*self.inner.share_commitment())
    }

    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str(json)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))
    }
}

impl From<SessionKeyShareProof> for PySessionKeyShareProof {
    fn from(inner: SessionKeyShareProof) -> Self {
        Self { inner }
    }
}

impl From<PySessionKeyShareProof> for SessionKeyShareProof {
    fn from(py: PySessionKeyShareProof) -> Self {
        py.inner
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBlindingCommitment>()?;
    m.add_class::<PyBlindingCommitments>()?;
    m.add_class::<PySessionKeyShareProof>()?;
    Ok(())
}
