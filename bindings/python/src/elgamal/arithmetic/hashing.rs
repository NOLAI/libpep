//! Python bindings for hashing to the group and to scalars (RFC 9380, RFC 9497).

use crate::elgamal::arithmetic::group_elements::PyGroupElement;
use crate::elgamal::arithmetic::scalars::PyScalarCanBeZero;
use libpep::elgamal::arithmetic::hashing;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::Sha512;

/// `expand_message_xmd` of RFC 9380 with SHA-512: expand `msg` under the domain separation tag
/// `dst` to `len_in_bytes` (at most 65535) uniformly pseudorandom bytes.
#[pyfunction]
#[pyo3(name = "expand_message_xmd_sha512")]
pub fn py_expand_message_xmd_sha512(
    py: Python,
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> PyResult<Py<PyAny>> {
    if len_in_bytes > 65535 {
        return Err(PyValueError::new_err("len_in_bytes must be at most 65535"));
    }
    let out = hashing::expand_message_xmd::<Sha512>(msg, dst, len_in_bytes);
    Ok(PyBytes::new(py, &out).into())
}

/// `hash_to_ristretto255` (RFC 9380) with SHA-512 under the complete domain separation tag
/// `dst`. Use `libpep.encodings.hash_to_group` to hash under a protocol context.
#[pyfunction]
#[pyo3(name = "hash_to_group")]
pub fn py_hash_to_group(msg: &[u8], dst: &[u8]) -> PyGroupElement {
    hashing::hash_to_group(msg, dst).into()
}

/// `HashToScalar` of the ristretto255-SHA512 ciphersuite of RFC 9497 under the complete domain
/// separation tag `dst`. The result can be zero.
#[pyfunction]
#[pyo3(name = "hash_to_scalar")]
pub fn py_hash_to_scalar(msg: &[u8], dst: &[u8]) -> PyScalarCanBeZero {
    hashing::hash_to_scalar(msg, dst).into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_expand_message_xmd_sha512, m)?)?;
    m.add_function(wrap_pyfunction!(py_hash_to_group, m)?)?;
    m.add_function(wrap_pyfunction!(py_hash_to_scalar, m)?)?;
    Ok(())
}
