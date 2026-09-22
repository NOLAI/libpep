//! Python bindings for the protocol context.

use libpep::protocol::{Context, Mode, RISTRETTO255_SHA512};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

/// The protocol mode, the second component of the context string.
#[pyclass(name = "Mode", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PyMode {
    /// Plain (non-verifiable) transcryption, `modeCoPRF = 0x00`.
    CoPRF = 0x00,
    /// Verifiable transcryption, `modeVcoPRF = 0x01`.
    VcoPRF = 0x01,
}

impl From<PyMode> for Mode {
    fn from(mode: PyMode) -> Self {
        match mode {
            PyMode::CoPRF => Mode::CoPRF,
            PyMode::VcoPRF => Mode::VcoPRF,
        }
    }
}

impl From<Mode> for PyMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::CoPRF => PyMode::CoPRF,
            Mode::VcoPRF => PyMode::VcoPRF,
        }
    }
}

/// The protocol context: mode and ciphersuite identifier, from which the context string
/// `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier` is built.
///
/// Every derived factor and hashed pseudonym is domain-separated with it, so all parties of a
/// deployment must use the same context. The default is `ristretto255-SHA512` in `Mode.CoPRF`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[pyclass(name = "Context", from_py_object)]
pub struct PyContext(pub(crate) Context);

#[pymethods]
impl PyContext {
    /// Create a context from a ciphersuite identifier (str or bytes, `ristretto255-SHA512` if
    /// omitted) and a mode (`Mode.CoPRF` if omitted).
    #[new]
    #[pyo3(signature = (identifier = None, mode = PyMode::CoPRF))]
    fn new(identifier: Option<&Bound<'_, PyAny>>, mode: PyMode) -> PyResult<Self> {
        let identifier = match identifier {
            None => RISTRETTO255_SHA512.as_bytes().to_vec(),
            Some(v) if v.is_instance_of::<PyString>() => v.extract::<String>()?.into_bytes(),
            Some(v) => v.extract::<Vec<u8>>()?,
        };
        Ok(Self(Context::new(mode.into(), identifier)))
    }

    /// The default context: `ristretto255-SHA512` in `Mode.CoPRF`.
    #[staticmethod]
    fn default() -> Self {
        Self(Context::default())
    }

    /// The protocol mode.
    #[getter]
    fn mode(&self) -> PyMode {
        self.0.mode.into()
    }

    /// The ciphersuite identifier.
    #[getter]
    fn identifier(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.identifier).into()
    }

    /// The context string `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier`.
    fn context_string(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.context_string()).into()
    }

    fn __repr__(&self) -> String {
        format!("Context({})", self.0)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __eq__(&self, other: &PyContext) -> bool {
        self.0 == other.0
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

/// The context of an optional argument, or the default context.
pub(crate) fn context_or_default(context: Option<&PyContext>) -> Context {
    context.map_or_else(Context::default, |c| c.0.clone())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMode>()?;
    m.add_class::<PyContext>()?;
    Ok(())
}
