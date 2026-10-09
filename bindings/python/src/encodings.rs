//! Python bindings for the encodings of identifiers and payloads as group elements.
//!
//! Every encoding must be such that no party can produce two encoded inputs with a known
//! discrete-log relation; encoding an identifier `x` as `x * G` is forbidden.

use crate::ciphersuite::{ciphersuite_or_current, PyCiphersuite};
use crate::elgamal::arithmetic::group_elements::PyGroupElement;
use libpep::encodings;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// The hash_to_group encoding of an identifier: hash_to_ristretto255 (RFC 9380) domain-separated
/// with the ciphersuite (`"HashToGroup-" || contextString`). Not invertible.
#[pyfunction]
#[pyo3(name = "hash_to_group", signature = (x, ciphersuite = None))]
pub fn py_hash_to_group(x: &[u8], ciphersuite: Option<&PyCiphersuite>) -> PyGroupElement {
    encodings::hash_to_group(x, &ciphersuite_or_current(ciphersuite)).into()
}

/// The lizard encoding of a 16-byte string as a group element. Invertible with `decode_lizard`.
#[pyfunction]
#[pyo3(name = "encode_lizard")]
pub fn py_encode_lizard(data: &[u8]) -> PyResult<PyGroupElement> {
    let data: &[u8; 16] = data
        .try_into()
        .map_err(|_| PyValueError::new_err("lizard encodes exactly 16 bytes"))?;
    Ok(encodings::encode_lizard(data).into())
}

/// Invert `encode_lizard`; `None` if the element is not a lizard encoding (such as a
/// reshuffled one).
#[pyfunction]
#[pyo3(name = "decode_lizard")]
pub fn py_decode_lizard(py: Python, element: &PyGroupElement) -> Option<Py<PyAny>> {
    encodings::decode_lizard(&element.0).map(|x| PyBytes::new(py, &x).into())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_hash_to_group, m)?)?;
    m.add_function(wrap_pyfunction!(py_encode_lizard, m)?)?;
    m.add_function(wrap_pyfunction!(py_decode_lizard, m)?)?;
    Ok(())
}
