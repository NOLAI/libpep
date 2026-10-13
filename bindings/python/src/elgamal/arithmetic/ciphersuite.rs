//! Python bindings for the ciphersuite.

use libpep::elgamal::arithmetic::{Ciphersuite, Group, Ristretto255};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// The ciphersuite identifier, from which the context string `"coPRFV1-" || identifier` is built.
///
/// Hashes that take no secret, in particular `hashing.hash_to_group`, are domain-separated with
/// it. An identifier names a group *and* a hash, so it belongs to the group rather than being
/// chosen per call; `ristretto255-SHA512` is the only suite this build implements.
///
/// This is not an `EncryptionContext` or a `PseudonymizationDomain`: those name a session and a
/// domain within a deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[pyclass(name = "Ciphersuite", from_py_object)]
pub struct PyCiphersuite(pub(crate) Ciphersuite);

#[pymethods]
impl PyCiphersuite {
    /// The ciphersuite of the group this build implements: `ristretto255-SHA512`.
    ///
    /// A ciphersuite cannot be constructed from an arbitrary identifier: it names a group and a
    /// hash together, and pairing one group's identifier with another group's operations would
    /// produce hashes tagged for the wrong curve.
    #[new]
    fn new() -> Self {
        Self::current()
    }

    /// The ciphersuite this build implements: `ristretto255-SHA512`.
    #[staticmethod]
    fn current() -> Self {
        Self(Ristretto255::CIPHERSUITE)
    }

    /// The ciphersuite identifier.
    #[getter]
    fn identifier(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.identifier().as_bytes()).into()
    }

    /// The context string `"coPRFV1-" || identifier`.
    ///
    /// The name is the spec's: RFC 9497 and draft-doesburg-cfrg-coprf both call this value
    /// `contextString`.
    fn context_string(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.context_string()).into()
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

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyCiphersuite>()?;
    Ok(())
}
