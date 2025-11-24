use super::super::contexts::*;
use crate::high_level::py::keys::{PyEncryptionSecret, PyPseudonymizationSecret};
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[pyclass(name = "ReshuffleFactor")]
pub struct PyReshuffleFactor(pub(crate) ReshuffleFactor);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[pyclass(name = "PseudonymRekeyFactor")]
pub struct PyPseudonymRekeyFactor(pub(crate) PseudonymRekeyFactor);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[pyclass(name = "AttributeRekeyFactor")]
pub struct PyAttributeRekeyFactor(pub(crate) AttributeRekeyFactor);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "PseudonymRSKFactors")]
pub struct PyPseudonymRSKFactors {
    #[pyo3(get)]
    pub s: PyReshuffleFactor,
    #[pyo3(get)]
    pub k: PyPseudonymRekeyFactor,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymizationInfo")]
pub struct PyPseudonymizationInfo(pub PyPseudonymRSKFactors);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeRekeyInfo")]
pub struct PyAttributeRekeyInfo(pub PyAttributeRekeyFactor);

#[derive(Copy, Clone, Debug)]
#[pyclass(name = "TranscryptionInfo")]
pub struct PyTranscryptionInfo {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymizationInfo,
    #[pyo3(get)]
    pub attribute: PyAttributeRekeyInfo,
}

#[pymethods]
impl PyPseudonymizationInfo {
    #[new]
    fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
        pseudonymization_secret: &PyPseudonymizationSecret,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        let x = PseudonymizationInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );
        let s = PyReshuffleFactor(x.s);
        let k = PyPseudonymRekeyFactor(x.k);
        PyPseudonymizationInfo(PyPseudonymRSKFactors { s, k })
    }

    #[getter]
    fn s(&self) -> PyReshuffleFactor {
        self.0.s
    }

    #[getter]
    fn k(&self) -> PyPseudonymRekeyFactor {
        self.0.k
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        PyPseudonymizationInfo(PyPseudonymRSKFactors {
            s: PyReshuffleFactor(ReshuffleFactor(self.0.s.0 .0.invert())),
            k: PyPseudonymRekeyFactor(PseudonymRekeyFactor(self.0.k.0 .0.invert())),
        })
    }
}

#[pymethods]
impl PyAttributeRekeyInfo {
    #[new]
    fn new(session_from: &str, session_to: &str, encryption_secret: &PyEncryptionSecret) -> Self {
        let x = AttributeRekeyInfo::new(
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &encryption_secret.0,
        );
        PyAttributeRekeyInfo(PyAttributeRekeyFactor(x))
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        PyAttributeRekeyInfo(PyAttributeRekeyFactor(AttributeRekeyFactor(
            self.0 .0 .0.invert(),
        )))
    }
}

#[pymethods]
impl PyTranscryptionInfo {
    #[new]
    fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
        pseudonymization_secret: &PyPseudonymizationSecret,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        let x = TranscryptionInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );
        Self {
            pseudonym: PyPseudonymizationInfo::from(x.pseudonym),
            attribute: PyAttributeRekeyInfo::from(x.attribute),
        }
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        Self {
            pseudonym: self.pseudonym.rev(),
            attribute: self.attribute.rev(),
        }
    }
}

impl From<PseudonymizationInfo> for PyPseudonymizationInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        let s = PyReshuffleFactor(x.s);
        let k = PyPseudonymRekeyFactor(x.k);
        PyPseudonymizationInfo(PyPseudonymRSKFactors { s, k })
    }
}

impl From<&PyPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &PyPseudonymizationInfo) -> Self {
        let s = x.s.0;
        let k = x.k.0;
        PseudonymizationInfo { s, k }
    }
}

impl From<AttributeRekeyInfo> for PyAttributeRekeyInfo {
    fn from(x: AttributeRekeyInfo) -> Self {
        PyAttributeRekeyInfo(PyAttributeRekeyFactor(x))
    }
}

impl From<&PyAttributeRekeyInfo> for AttributeRekeyInfo {
    fn from(x: &PyAttributeRekeyInfo) -> Self {
        x.0 .0
    }
}

impl From<TranscryptionInfo> for PyTranscryptionInfo {
    fn from(x: TranscryptionInfo) -> Self {
        Self {
            pseudonym: PyPseudonymizationInfo::from(x.pseudonym),
            attribute: PyAttributeRekeyInfo::from(x.attribute),
        }
    }
}

impl From<&PyTranscryptionInfo> for TranscryptionInfo {
    fn from(x: &PyTranscryptionInfo) -> Self {
        Self {
            pseudonym: PseudonymizationInfo::from(&x.pseudonym),
            attribute: AttributeRekeyInfo::from(&x.attribute),
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyReshuffleFactor>()?;
    m.add_class::<PyPseudonymRekeyFactor>()?;
    m.add_class::<PyAttributeRekeyFactor>()?;
    m.add_class::<PyPseudonymRSKFactors>()?;
    m.add_class::<PyPseudonymizationInfo>()?;
    m.add_class::<PyAttributeRekeyInfo>()?;
    m.add_class::<PyTranscryptionInfo>()?;
    Ok(())
}
