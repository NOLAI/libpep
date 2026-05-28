//! Python bindings for verifiable Carter-Wegman factor derivation.
//!
//! Mirrors `crate::factors::verifiable`. Only available with
//! `feature = "verifiable-derivation"`.

#![cfg(feature = "verifiable-derivation")]

use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::factors::py::contexts::{PyEncryptionContext, PyPseudonymizationDomain};
use crate::factors::verifiable::{
    MasterPseudonymizationPublicKey, MasterPseudonymizationSecret, MasterRekeyingPublicKey,
    MasterRekeyingSecret,
};
use pyo3::prelude::*;

#[cfg(feature = "serde")]
use pyo3::exceptions::PyValueError;

/// Master pseudonymization secret with two Carter-Wegman components.
#[pyclass(name = "MasterPseudonymizationSecret", from_py_object)]
#[derive(Clone)]
pub struct PyMasterPseudonymizationSecret {
    pub(crate) inner: MasterPseudonymizationSecret,
}

#[pymethods]
impl PyMasterPseudonymizationSecret {
    /// Generate a new random master pseudonymization secret.
    #[new]
    fn new() -> Self {
        let mut rng = rand::rng();
        Self {
            inner: MasterPseudonymizationSecret::random(&mut rng),
        }
    }

    /// Generate a new random master pseudonymization secret (alias).
    #[staticmethod]
    fn random() -> Self {
        let mut rng = rand::rng();
        Self {
            inner: MasterPseudonymizationSecret::random(&mut rng),
        }
    }

    /// Derive the public key for this secret.
    fn to_public_key(&self) -> PyMasterPseudonymizationPublicKey {
        PyMasterPseudonymizationPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Derive a reshuffling factor for a domain.
    ///
    /// Returns the scalar `s_d = x₁·H₁(d) + x₂·H₂(d)` as a non-zero scalar.
    fn derive_reshuffle_factor(
        &self,
        domain: &PyPseudonymizationDomain,
    ) -> crate::arithmetic::py::scalars::PyScalarNonZero {
        crate::arithmetic::py::scalars::PyScalarNonZero(
            self.inner.derive_reshuffle_factor(&domain.0),
        )
    }
}

impl From<MasterPseudonymizationSecret> for PyMasterPseudonymizationSecret {
    fn from(inner: MasterPseudonymizationSecret) -> Self {
        Self { inner }
    }
}

impl From<PyMasterPseudonymizationSecret> for MasterPseudonymizationSecret {
    fn from(py: PyMasterPseudonymizationSecret) -> Self {
        py.inner
    }
}

/// Master pseudonymization public key `(X₁, X₂)`.
#[pyclass(name = "MasterPseudonymizationPublicKey", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyMasterPseudonymizationPublicKey {
    pub(crate) inner: MasterPseudonymizationPublicKey,
}

#[pymethods]
impl PyMasterPseudonymizationPublicKey {
    /// Construct from two group elements `X₁` and `X₂`.
    #[new]
    fn new(x1: PyGroupElement, x2: PyGroupElement) -> Self {
        Self {
            inner: MasterPseudonymizationPublicKey { x1: x1.0, x2: x2.0 },
        }
    }

    #[getter]
    fn x1(&self) -> PyGroupElement {
        PyGroupElement(self.inner.x1)
    }

    #[getter]
    fn x2(&self) -> PyGroupElement {
        PyGroupElement(self.inner.x2)
    }

    /// Compute the reshuffle factor commitment `S_d = s_d·G` for a domain.
    fn compute_reshuffle_commitment(&self, domain: &PyPseudonymizationDomain) -> PyGroupElement {
        PyGroupElement(self.inner.compute_reshuffle_commitment(&domain.0))
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

impl From<MasterPseudonymizationPublicKey> for PyMasterPseudonymizationPublicKey {
    fn from(inner: MasterPseudonymizationPublicKey) -> Self {
        Self { inner }
    }
}

impl From<PyMasterPseudonymizationPublicKey> for MasterPseudonymizationPublicKey {
    fn from(py: PyMasterPseudonymizationPublicKey) -> Self {
        py.inner
    }
}

/// Master rekeying secret with two Carter-Wegman components.
#[pyclass(name = "MasterRekeyingSecret", from_py_object)]
#[derive(Clone)]
pub struct PyMasterRekeyingSecret {
    pub(crate) inner: MasterRekeyingSecret,
}

#[pymethods]
impl PyMasterRekeyingSecret {
    /// Generate a new random master rekeying secret.
    #[new]
    fn new() -> Self {
        let mut rng = rand::rng();
        Self {
            inner: MasterRekeyingSecret::random(&mut rng),
        }
    }

    /// Generate a new random master rekeying secret (alias).
    #[staticmethod]
    fn random() -> Self {
        let mut rng = rand::rng();
        Self {
            inner: MasterRekeyingSecret::random(&mut rng),
        }
    }

    /// Derive the public key for this secret.
    fn to_public_key(&self) -> PyMasterRekeyingPublicKey {
        PyMasterRekeyingPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Derive a pseudonym rekeying factor for a context.
    fn derive_pseudonym_rekey(
        &self,
        context: &PyEncryptionContext,
    ) -> crate::arithmetic::py::scalars::PyScalarNonZero {
        crate::arithmetic::py::scalars::PyScalarNonZero(
            self.inner.derive_pseudonym_rekey_factor(&context.0),
        )
    }

    /// Derive an attribute rekeying factor for a context.
    fn derive_attribute_rekey(
        &self,
        context: &PyEncryptionContext,
    ) -> crate::arithmetic::py::scalars::PyScalarNonZero {
        crate::arithmetic::py::scalars::PyScalarNonZero(
            self.inner.derive_attribute_rekey_factor(&context.0),
        )
    }
}

impl From<MasterRekeyingSecret> for PyMasterRekeyingSecret {
    fn from(inner: MasterRekeyingSecret) -> Self {
        Self { inner }
    }
}

impl From<PyMasterRekeyingSecret> for MasterRekeyingSecret {
    fn from(py: PyMasterRekeyingSecret) -> Self {
        py.inner
    }
}

/// Master rekeying public key `(Y₁, Y₂)`.
#[pyclass(name = "MasterRekeyingPublicKey", from_py_object)]
#[derive(Clone, Copy)]
pub struct PyMasterRekeyingPublicKey {
    pub(crate) inner: MasterRekeyingPublicKey,
}

#[pymethods]
impl PyMasterRekeyingPublicKey {
    /// Construct from two group elements `Y₁` and `Y₂`.
    #[new]
    fn new(y1: PyGroupElement, y2: PyGroupElement) -> Self {
        Self {
            inner: MasterRekeyingPublicKey { y1: y1.0, y2: y2.0 },
        }
    }

    #[getter]
    fn y1(&self) -> PyGroupElement {
        PyGroupElement(self.inner.y1)
    }

    #[getter]
    fn y2(&self) -> PyGroupElement {
        PyGroupElement(self.inner.y2)
    }

    /// Compute the pseudonym rekey factor commitment `K_s = k_s·G` for a context.
    fn compute_pseudonym_rekey_commitment(&self, context: &PyEncryptionContext) -> PyGroupElement {
        PyGroupElement(self.inner.compute_pseudonym_rekey_commitment(&context.0))
    }

    /// Compute the attribute rekey factor commitment for a context.
    fn compute_attribute_rekey_commitment(&self, context: &PyEncryptionContext) -> PyGroupElement {
        PyGroupElement(self.inner.compute_attribute_rekey_commitment(&context.0))
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

impl From<MasterRekeyingPublicKey> for PyMasterRekeyingPublicKey {
    fn from(inner: MasterRekeyingPublicKey) -> Self {
        Self { inner }
    }
}

impl From<PyMasterRekeyingPublicKey> for MasterRekeyingPublicKey {
    fn from(py: PyMasterRekeyingPublicKey) -> Self {
        py.inner
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMasterPseudonymizationSecret>()?;
    m.add_class::<PyMasterPseudonymizationPublicKey>()?;
    m.add_class::<PyMasterRekeyingSecret>()?;
    m.add_class::<PyMasterRekeyingPublicKey>()?;
    Ok(())
}
