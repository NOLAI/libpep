//! Python bindings for the ciphersuite and the hashing that runs under it.

pub mod hashing;

use libpep::ciphersuite::{Ciphersuite, CiphersuiteId, Ristretto255Sha512};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// The ciphersuite identifier, from which the context string `"nPEPV1-" || identifier` is built.
///
/// Hashes that take no secret, in particular `hashing.hash_to_group`, are domain-separated with
/// it. An identifier names a group and a hash together, so it is not chosen per call: a build
/// has the suite `ristretto255-SHA512`, ristretto255 with SHA-512.
///
/// A ciphersuite is unrelated to an `EncryptionContext` or a `PseudonymizationDomain`, which
/// name a session and a domain within a deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[pyclass(name = "CiphersuiteId", from_py_object)]
pub struct PyCiphersuiteId(pub(crate) CiphersuiteId);

#[pymethods]
impl PyCiphersuiteId {
    /// The ciphersuite of this build: `ristretto255-SHA512`.
    ///
    /// A ciphersuite cannot be constructed from an arbitrary identifier. It names a group and a
    /// hash together, and an identifier paired with the wrong operations would produce hashes
    /// tagged for the wrong suite.
    #[new]
    fn new() -> Self {
        Self::current()
    }

    /// The ciphersuite this build implements: `ristretto255-SHA512`.
    #[staticmethod]
    fn current() -> Self {
        Self(Ristretto255Sha512::ID)
    }

    /// The ciphersuite identifier.
    #[getter]
    fn identifier(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.identifier().as_bytes()).into()
    }

    /// The context string `"nPEPV1-" || identifier`.
    fn context_string(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.context_string()).into()
    }

    fn __repr__(&self) -> String {
        format!("CiphersuiteId({})", self.0)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __eq__(&self, other: &PyCiphersuiteId) -> bool {
        self.0 == other.0
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register(m)?;
    crate::add_submodule(m, "libpep.ciphersuite.hashing", |sm| hashing::register(sm))?;
    Ok(())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyCiphersuiteId>()?;
    Ok(())
}
