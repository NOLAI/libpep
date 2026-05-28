//! Python bindings for zero-knowledge proofs.

use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::arithmetic::py::scalars::PyScalarNonZero;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// A zero-knowledge proof demonstrating knowledge of a discrete logarithm.
///
/// This proof shows that `N = a*M` for some secret scalar `a` without revealing `a`.
#[pyclass(name = "Proof", from_py_object)]
#[derive(Clone)]
pub struct PyProof {
    pub(crate) inner: Proof,
}

#[pymethods]
impl PyProof {
    /// Encodes the proof as a base64 string.
    fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    /// Decodes a proof from a base64 string.
    #[staticmethod]
    fn from_base64(s: &str) -> PyResult<Self> {
        Proof::from_base64(s)
            .map(|inner| PyProof { inner })
            .ok_or_else(|| PyValueError::new_err("Invalid base64 encoded proof"))
    }

    /// Encodes the proof as a hex string.
    fn to_hex(&self) -> String {
        hex::encode(self.inner.encode())
    }

    /// Decodes a proof from a hex string.
    #[staticmethod]
    fn from_hex(s: &str) -> PyResult<Self> {
        let bytes = hex::decode(s).map_err(|e| PyValueError::new_err(format!("{}", e)))?;
        if bytes.len() != 128 {
            return Err(PyValueError::new_err("Invalid proof length"));
        }
        let mut arr = [0u8; 128];
        arr.copy_from_slice(&bytes);
        Proof::decode(&arr)
            .map(|inner| PyProof { inner })
            .ok_or_else(|| PyValueError::new_err("Invalid proof encoding"))
    }

    /// Returns the encoded bytes of the proof.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode())
    }

    /// Decodes a proof from bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        if bytes.len() != 128 {
            return Err(PyValueError::new_err("Invalid proof length"));
        }
        let mut arr = [0u8; 128];
        arr.copy_from_slice(bytes);
        Proof::decode(&arr)
            .map(|inner| PyProof { inner })
            .ok_or_else(|| PyValueError::new_err("Invalid proof encoding"))
    }

    fn __repr__(&self) -> String {
        format!("Proof({})", self.to_base64())
    }

    fn __str__(&self) -> String {
        self.to_base64()
    }
}

/// Creates a zero-knowledge proof.
///
/// Returns a tuple `(public_key, proof)` where `public_key = a*G`.
#[pyfunction]
fn create_zkp_proof(
    secret: &PyScalarNonZero,
    message: &PyGroupElement,
) -> (PyGroupElement, PyProof) {
    let mut rng = rand::rng();
    let (public_key, proof) = create_proof(&secret.0, &message.0, &mut rng);
    (PyGroupElement(public_key), PyProof { inner: proof })
}

/// Verifies a zero-knowledge proof.
#[pyfunction]
fn verify_zkp_proof(
    public_key: &PyGroupElement,
    message: &PyGroupElement,
    proof: &PyProof,
) -> bool {
    verify_proof(&public_key.0, &message.0, &proof.inner)
}

/// Register the zkps module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyProof>()?;
    m.add_function(wrap_pyfunction!(create_zkp_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_zkp_proof, m)?)?;
    Ok(())
}
