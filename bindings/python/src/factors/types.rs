//! Python bindings for factor types and the transcryption info types that bundle them.

use crate::contexts::{PyEncryptionContext, PyPseudonymizationDomain};
use crate::elgamal::arithmetic::PyScalarNonZero;
use crate::factors::secrets::{PyEncryptionSecret, PyPseudonymizationSecret};
use derive_more::{Deref, From, Into};
use libpep::factors::types::*;
use pyo3::prelude::*;

/// A factor used to rerandomize an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "RerandomizeFactor", from_py_object)]
pub struct PyRerandomizeFactor(pub(crate) RerandomizeFactor);

#[pymethods]
impl PyRerandomizeFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(RerandomizeFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0.scalar())
    }
}

/// A factor used to reshuffle an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "ReshuffleFactor", from_py_object)]
pub struct PyReshuffleFactor(pub(crate) ReshuffleFactor);

#[pymethods]
impl PyReshuffleFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(ReshuffleFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0.scalar())
    }
}

/// A factor used to rekey pseudonyms between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "PseudonymRekeyFactor", from_py_object)]
pub struct PyPseudonymRekeyFactor(pub(crate) PseudonymRekeyFactor);

#[pymethods]
impl PyPseudonymRekeyFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(PseudonymRekeyFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0.scalar())
    }
}

/// A factor used to rekey attributes between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "AttributeRekeyFactor", from_py_object)]
pub struct PyAttributeRekeyFactor(pub(crate) AttributeRekeyFactor);

#[pymethods]
impl PyAttributeRekeyFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(AttributeRekeyFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0.scalar())
    }
}

/// The information required to pseudonymize from one domain and session to another.
///
/// Bundles a reshuffle factor `s` and a pseudonym rekey factor `k`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "PseudonymizationInfo", from_py_object)]
pub struct PyPseudonymizationInfo(pub(crate) PseudonymizationInfo);

#[pymethods]
impl PyPseudonymizationInfo {
    #[new]
    fn new(
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
        pseudonymization_secret: &PyPseudonymizationSecret,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        Self(PseudonymizationInfo::new(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
        ))
    }

    /// The reshuffle factor.
    #[getter]
    fn s(&self) -> PyReshuffleFactor {
        PyReshuffleFactor(self.0.s)
    }

    /// The pseudonym rekey factor.
    #[getter]
    fn k(&self) -> PyPseudonymRekeyFactor {
        PyPseudonymRekeyFactor(self.0.k)
    }

    /// The rekey-only part of this info, for rekeying pseudonyms without reshuffling.
    #[getter]
    fn rekey_info(&self) -> PyPseudonymRekeyInfo {
        PyPseudonymRekeyInfo(self.0.into())
    }

    /// The info for the opposite direction.
    fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

/// The information required to rekey pseudonyms from one session to another.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "PseudonymRekeyInfo", from_py_object)]
pub struct PyPseudonymRekeyInfo(pub(crate) PseudonymRekeyInfo);

#[pymethods]
impl PyPseudonymRekeyInfo {
    #[new]
    fn new(
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        Self(PseudonymRekeyInfo::new(
            &session_from.0,
            &session_to.0,
            &encryption_secret.0,
        ))
    }

    /// The pseudonym rekey factor.
    #[getter]
    fn k(&self) -> PyPseudonymRekeyFactor {
        PyPseudonymRekeyFactor(self.0.k)
    }

    /// The info for the opposite direction.
    fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

/// The information required to rekey attributes from one session to another.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "AttributeRekeyInfo", from_py_object)]
pub struct PyAttributeRekeyInfo(pub(crate) AttributeRekeyInfo);

#[pymethods]
impl PyAttributeRekeyInfo {
    #[new]
    fn new(
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        Self(AttributeRekeyInfo::new(
            &session_from.0,
            &session_to.0,
            &encryption_secret.0,
        ))
    }

    /// The attribute rekey factor.
    #[getter]
    fn k(&self) -> PyAttributeRekeyFactor {
        PyAttributeRekeyFactor(self.0.k)
    }

    /// The info for the opposite direction.
    fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

/// The information required to transcrypt from one domain and session to another.
///
/// Bundles pseudonymization info for pseudonyms and rekey info for attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "TranscryptionInfo", from_py_object)]
pub struct PyTranscryptionInfo(pub(crate) TranscryptionInfo);

#[pymethods]
impl PyTranscryptionInfo {
    #[new]
    fn new(
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
        pseudonymization_secret: &PyPseudonymizationSecret,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        Self(TranscryptionInfo::new(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
        ))
    }

    /// The pseudonymization info for pseudonyms.
    #[getter]
    fn pseudonym(&self) -> PyPseudonymizationInfo {
        PyPseudonymizationInfo(self.0.pseudonym)
    }

    /// The rekey info for attributes.
    #[getter]
    fn attribute(&self) -> PyAttributeRekeyInfo {
        PyAttributeRekeyInfo(self.0.attribute)
    }

    /// The info for the opposite direction.
    fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

impl From<&PyPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &PyPseudonymizationInfo) -> Self {
        x.0
    }
}

impl From<&PyPseudonymRekeyInfo> for PseudonymRekeyInfo {
    fn from(x: &PyPseudonymRekeyInfo) -> Self {
        x.0
    }
}

impl From<&PyAttributeRekeyInfo> for AttributeRekeyInfo {
    fn from(x: &PyAttributeRekeyInfo) -> Self {
        x.0
    }
}

impl From<&PyTranscryptionInfo> for TranscryptionInfo {
    fn from(x: &PyTranscryptionInfo) -> Self {
        x.0
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRerandomizeFactor>()?;
    m.add_class::<PyReshuffleFactor>()?;
    m.add_class::<PyPseudonymRekeyFactor>()?;
    m.add_class::<PyAttributeRekeyFactor>()?;
    m.add_class::<PyPseudonymizationInfo>()?;
    m.add_class::<PyPseudonymRekeyInfo>()?;
    m.add_class::<PyAttributeRekeyInfo>()?;
    m.add_class::<PyTranscryptionInfo>()?;
    Ok(())
}
