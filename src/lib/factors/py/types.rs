//! Python bindings for cryptographic factor types.

use crate::arithmetic::py::PyScalarNonZero;
use crate::factors::types::*;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

/// A factor used to rerandomize an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "RerandomizeFactor")]
pub struct PyRerandomizeFactor(pub(crate) RerandomizeFactor);

#[pymethods]
impl PyRerandomizeFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(RerandomizeFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0 .0)
    }
}

/// A factor used to reshuffle an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "ReshuffleFactor")]
pub struct PyReshuffleFactor(pub(crate) ReshuffleFactor);

#[pymethods]
impl PyReshuffleFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(ReshuffleFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0 .0)
    }
}

/// A factor used to rekey pseudonyms between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "PseudonymRekeyFactor")]
pub struct PyPseudonymRekeyFactor(pub(crate) PseudonymRekeyFactor);

#[pymethods]
impl PyPseudonymRekeyFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(PseudonymRekeyFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0 .0)
    }
}

/// A factor used to rekey attributes between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[pyclass(name = "AttributeRekeyFactor")]
pub struct PyAttributeRekeyFactor(pub(crate) AttributeRekeyFactor);

#[pymethods]
impl PyAttributeRekeyFactor {
    #[new]
    pub fn new(scalar: &PyScalarNonZero) -> Self {
        Self(AttributeRekeyFactor::from(scalar.0))
    }

    #[pyo3(name = "scalar")]
    pub fn py_scalar(&self) -> PyScalarNonZero {
        PyScalarNonZero(self.0 .0)
    }
}

/// Factors for pseudonymization containing reshuffle and rekey factors.
#[derive(Clone, Copy)]
#[pyclass(name = "PseudonymRSKFactors")]
pub struct PyPseudonymRSKFactors {
    #[pyo3(get, set)]
    pub s: PyReshuffleFactor,
    #[pyo3(get, set)]
    pub k: PyPseudonymRekeyFactor,
}

#[pymethods]
impl PyPseudonymRSKFactors {
    #[new]
    pub fn new(s: PyReshuffleFactor, k: PyPseudonymRekeyFactor) -> Self {
        Self { s, k }
    }
}

impl From<&PyPseudonymRSKFactors> for PseudonymRSKFactors {
    fn from(x: &PyPseudonymRSKFactors) -> Self {
        PseudonymRSKFactors { s: x.s.0, k: x.k.0 }
    }
}

impl From<PseudonymRSKFactors> for PyPseudonymRSKFactors {
    fn from(x: PseudonymRSKFactors) -> Self {
        PyPseudonymRSKFactors {
            s: PyReshuffleFactor(x.s),
            k: PyPseudonymRekeyFactor(x.k),
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRerandomizeFactor>()?;
    m.add_class::<PyReshuffleFactor>()?;
    m.add_class::<PyPseudonymRekeyFactor>()?;
    m.add_class::<PyAttributeRekeyFactor>()?;
    m.add_class::<PyPseudonymRSKFactors>()?;
    Ok(())
}
