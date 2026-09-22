//! Python bindings for the wire formats of draft-doesburg-cfrg-coprf: batch requests and
//! responses as bytes in, bytes out.

use crate::elgamal::arithmetic::PyGroupElement;
use crate::elgamal::PyElGamal;
use derive_more::{Deref, From, Into};
use libpep::wire::{BatchKind, BatchRequest, BatchResponse};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};

/// The kind of data in a batch: pseudonyms (reshuffled and rekeyed) or attributes (rekeyed).
#[pyclass(name = "BatchKind", eq, eq_int, from_py_object)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PyBatchKind {
    Pseudonym = 0x01,
    Attribute = 0x02,
}

impl From<PyBatchKind> for BatchKind {
    fn from(kind: PyBatchKind) -> Self {
        match kind {
            PyBatchKind::Pseudonym => BatchKind::Pseudonym,
            PyBatchKind::Attribute => BatchKind::Attribute,
        }
    }
}

impl From<BatchKind> for PyBatchKind {
    fn from(kind: BatchKind) -> Self {
        match kind {
            BatchKind::Pseudonym => PyBatchKind::Pseudonym,
            BatchKind::Attribute => PyBatchKind::Attribute,
        }
    }
}

/// An identifier argument: `bytes`, or `str` for its UTF-8 encoding.
fn identifier(arg: &Bound<PyAny>, what: &str) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = arg.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    if let Ok(text) = arg.extract::<String>() {
        return Ok(text.into_bytes());
    }
    Err(PyTypeError::new_err(format!("{what} must be bytes or str")))
}

fn value_error(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// The `BatchRequest` struct of draft-doesburg-cfrg-coprf: ciphertexts of one kind to transcrypt.
///
/// Carries the four identifiers (domain and context, from and to), the public key the items are
/// encrypted under, and the items.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "BatchRequest", from_py_object)]
pub struct PyBatchRequest(pub(crate) BatchRequest);

#[pymethods]
impl PyBatchRequest {
    /// Assemble a request. Identifiers are `bytes` or `str`; `items` are the ciphertexts,
    /// encrypted under `y_from`. Raises `ValueError` for an empty batch or an oversized field.
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        kind: PyBatchKind,
        d_from: &Bound<PyAny>,
        d_to: &Bound<PyAny>,
        c_from: &Bound<PyAny>,
        c_to: &Bound<PyAny>,
        y_from: &PyGroupElement,
        items: Vec<PyElGamal>,
    ) -> PyResult<Self> {
        BatchRequest::new(
            kind.into(),
            identifier(d_from, "d_from")?,
            identifier(d_to, "d_to")?,
            identifier(c_from, "c_from")?,
            identifier(c_to, "c_to")?,
            y_from.0,
            items.into_iter().map(|e| e.0).collect(),
        )
        .map(Self)
        .map_err(value_error)
    }

    /// Encode as the draft's `BatchRequest` struct.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Decode the draft's `BatchRequest` struct. Raises `ValueError` for an unknown type,
    /// truncated input, trailing bytes, an empty batch or an invalid element.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> PyResult<Self> {
        BatchRequest::from_bytes(bytes)
            .map(Self)
            .map_err(value_error)
    }

    /// The kind of data in the batch.
    #[getter]
    fn kind(&self) -> PyBatchKind {
        self.0.kind().into()
    }

    /// The pseudonymization domain the data comes from.
    #[getter]
    fn d_from(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.d_from()).into()
    }

    /// The pseudonymization domain the data goes to.
    #[getter]
    fn d_to(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.d_to()).into()
    }

    /// The encryption context the data comes from.
    #[getter]
    fn c_from(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.c_from()).into()
    }

    /// The encryption context the data goes to.
    #[getter]
    fn c_to(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, self.0.c_to()).into()
    }

    /// The public key the items are encrypted under.
    #[getter]
    fn y_from(&self) -> PyGroupElement {
        PyGroupElement(*self.0.y_from())
    }

    /// The ciphertexts.
    #[getter]
    fn items(&self) -> Vec<PyElGamal> {
        self.0.items().iter().copied().map(PyElGamal).collect()
    }

    fn __len__(&self) -> usize {
        self.0.items().len()
    }

    fn __repr__(&self) -> String {
        format!(
            "BatchRequest({:?}, {} items)",
            self.0.kind(),
            self.0.items().len()
        )
    }

    fn __eq__(&self, other: &PyBatchRequest) -> bool {
        self.0 == other.0
    }
}

/// The `BatchResponse` struct of draft-doesburg-cfrg-coprf: the transcrypted items and their key.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "BatchResponse", from_py_object)]
pub struct PyBatchResponse(pub(crate) BatchResponse);

#[pymethods]
impl PyBatchResponse {
    /// Assemble a response. Raises `ValueError` for an empty batch.
    #[new]
    fn new(y_to: &PyGroupElement, items: Vec<PyElGamal>) -> PyResult<Self> {
        BatchResponse::new(y_to.0, items.into_iter().map(|e| e.0).collect())
            .map(Self)
            .map_err(value_error)
    }

    /// Encode as the draft's `BatchResponse` struct.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Decode the draft's `BatchResponse` struct. Raises `ValueError` for truncated input,
    /// trailing bytes, an empty batch or an invalid element.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> PyResult<Self> {
        BatchResponse::from_bytes(bytes)
            .map(Self)
            .map_err(value_error)
    }

    /// The public key the items are now encrypted under.
    #[getter]
    fn y_to(&self) -> PyGroupElement {
        PyGroupElement(*self.0.y_to())
    }

    /// The transcrypted ciphertexts.
    #[getter]
    fn items(&self) -> Vec<PyElGamal> {
        self.0.items().iter().copied().map(PyElGamal).collect()
    }

    fn __len__(&self) -> usize {
        self.0.items().len()
    }

    fn __repr__(&self) -> String {
        format!("BatchResponse({} items)", self.0.items().len())
    }

    fn __eq__(&self, other: &PyBatchResponse) -> bool {
        self.0 == other.0
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBatchKind>()?;
    m.add_class::<PyBatchRequest>()?;
    m.add_class::<PyBatchResponse>()?;
    Ok(())
}
