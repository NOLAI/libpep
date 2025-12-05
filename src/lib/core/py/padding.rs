//! Python bindings for PKCS#7 padding operations on Pseudonym and Attribute types.
//!
//! Note: These are also exposed as methods on PyPseudonym and PyAttribute in core.rs.
//! This module provides standalone function versions for API completeness.

use super::data::{PyAttribute, PyPseudonym};
use crate::core::data::{Attribute, Pseudonym};
use crate::core::padding::Padded;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};

/// Encodes a byte array (up to 15 bytes) into a `Pseudonym` using PKCS#7 padding.
#[pyfunction]
#[pyo3(name = "pseudonym_from_bytes_padded")]
pub fn py_pseudonym_from_bytes_padded(data: &[u8]) -> PyResult<PyPseudonym> {
    Pseudonym::from_bytes_padded(data)
        .map(PyPseudonym)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
}

/// Encodes a string (up to 15 bytes) into a `Pseudonym` using PKCS#7 padding.
#[pyfunction]
#[pyo3(name = "pseudonym_from_string_padded")]
pub fn py_pseudonym_from_string_padded(text: &str) -> PyResult<PyPseudonym> {
    Pseudonym::from_string_padded(text)
        .map(PyPseudonym)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
}

/// Decodes a `Pseudonym` back to the original string.
#[pyfunction]
#[pyo3(name = "pseudonym_to_string_padded")]
pub fn py_pseudonym_to_string_padded(pseudonym: &PyPseudonym) -> PyResult<String> {
    pseudonym
        .0
        .to_string_padded()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
}

/// Decodes a `Pseudonym` back to the original byte array.
#[pyfunction]
#[pyo3(name = "pseudonym_to_bytes_padded")]
pub fn py_pseudonym_to_bytes_padded(py: Python, pseudonym: &PyPseudonym) -> PyResult<Py<PyAny>> {
    let result = pseudonym
        .0
        .to_bytes_padded()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

/// Encodes a byte array (up to 15 bytes) into an `Attribute` using PKCS#7 padding.
#[pyfunction]
#[pyo3(name = "attribute_from_bytes_padded")]
pub fn py_attribute_from_bytes_padded(data: &[u8]) -> PyResult<PyAttribute> {
    Attribute::from_bytes_padded(data)
        .map(PyAttribute)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
}

/// Encodes a string (up to 15 bytes) into an `Attribute` using PKCS#7 padding.
#[pyfunction]
#[pyo3(name = "attribute_from_string_padded")]
pub fn py_attribute_from_string_padded(text: &str) -> PyResult<PyAttribute> {
    Attribute::from_string_padded(text)
        .map(PyAttribute)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
}

/// Decodes an `Attribute` back to the original string.
#[pyfunction]
#[pyo3(name = "attribute_to_string_padded")]
pub fn py_attribute_to_string_padded(attribute: &PyAttribute) -> PyResult<String> {
    attribute
        .0
        .to_string_padded()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
}

/// Decodes an `Attribute` back to the original byte array.
#[pyfunction]
#[pyo3(name = "attribute_to_bytes_padded")]
pub fn py_attribute_to_bytes_padded(py: Python, attribute: &PyAttribute) -> PyResult<Py<PyAny>> {
    let result = attribute
        .0
        .to_bytes_padded()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))?;
    Ok(PyBytes::new(py, &result).into())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_pseudonym_from_bytes_padded, m)?)?;
    m.add_function(wrap_pyfunction!(py_pseudonym_from_string_padded, m)?)?;
    m.add_function(wrap_pyfunction!(py_pseudonym_to_string_padded, m)?)?;
    m.add_function(wrap_pyfunction!(py_pseudonym_to_bytes_padded, m)?)?;
    m.add_function(wrap_pyfunction!(py_attribute_from_bytes_padded, m)?)?;
    m.add_function(wrap_pyfunction!(py_attribute_from_string_padded, m)?)?;
    m.add_function(wrap_pyfunction!(py_attribute_to_string_padded, m)?)?;
    m.add_function(wrap_pyfunction!(py_attribute_to_bytes_padded, m)?)?;
    Ok(())
}
