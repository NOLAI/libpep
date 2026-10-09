//! Python bindings for the ciphersuite.

use libpep::ciphersuite::{Ciphersuite, RISTRETTO255_SHA512};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

/// The ciphersuite identifier, from which the context string `"coPRFV1-" || identifier` is built.
///
/// Hashes that take no secret, in particular `encodings.hash_to_group`, are domain-separated with
/// it, so all parties of a deployment must use the same one. The default, and the only suite this
/// build implements, is `ristretto255-SHA512`.
///
/// This is not an `EncryptionContext` or a `PseudonymizationDomain`: those name a session and a
/// domain within a deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[pyclass(name = "Ciphersuite", from_py_object)]
pub struct PyCiphersuite(pub(crate) Ciphersuite);

#[pymethods]
impl PyCiphersuite {
    /// Create a ciphersuite from an identifier (str or bytes, `ristretto255-SHA512` if omitted).
    #[new]
    #[pyo3(signature = (identifier = None))]
    fn new(identifier: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let identifier = match identifier {
            None => RISTRETTO255_SHA512.as_bytes().to_vec(),
            Some(v) if v.is_instance_of::<PyString>() => v.extract::<String>()?.into_bytes(),
            Some(v) => v.extract::<Vec<u8>>()?,
        };
        Ok(Self(Ciphersuite::new(identifier)))
    }

    /// The ciphersuite this build implements: `ristretto255-SHA512`.
    #[staticmethod]
    fn current() -> Self {
        Self(Ciphersuite::current())
    }

    /// The ciphersuite identifier.
    #[getter]
    fn identifier(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.identifier()).into()
    }

    /// The context string `"coPRFV1-" || identifier`.
    ///
    /// The name is the spec's: RFC 9497 and draft-doesburg-cfrg-coprf both call this value
    /// `contextString`.
    fn context_string(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.context_string()).into()
    }

    fn __repr__(&self) -> String {
        format!("Ciphersuite({})", self.0)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __eq__(&self, other: &PyCiphersuite) -> bool {
        self.0 == other.0
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

/// The ciphersuite of an optional argument, or the one this build implements.
pub(crate) fn ciphersuite_or_current(ciphersuite: Option<&PyCiphersuite>) -> Ciphersuite {
    ciphersuite.map_or_else(Ciphersuite::current, |c| c.0.clone())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyCiphersuite>()?;
    Ok(())
}
