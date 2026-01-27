//! Python bindings for zero-knowledge proofs.

use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// A zero-knowledge proof demonstrating knowledge of a discrete logarithm.
///
/// This proof shows that `N = a*M` for some secret scalar `a` without revealing `a`.
#[pyclass(name = "Proof")]
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
/// Args:
///     secret: The secret scalar as 32 bytes
///     message: The message as a group element (32 bytes)
///
/// Returns:
///     A tuple of (public_key, proof) where public_key is 32 bytes
#[pyfunction]
fn create_zkp_proof<'py>(
    py: Python<'py>,
    secret: &[u8],
    message: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, PyProof)> {
    let mut rng = rand::rng();

    let secret = ScalarNonZero::from_slice(secret)
        .ok_or_else(|| PyValueError::new_err("Invalid secret scalar"))?;
    let message = GroupElement::from_slice(message)
        .ok_or_else(|| PyValueError::new_err("Invalid message group element"))?;

    let (public_key, proof) = create_proof(&secret, &message, &mut rng);

    Ok((
        PyBytes::new(py, public_key.to_bytes().as_slice()),
        PyProof { inner: proof },
    ))
}

/// Verifies a zero-knowledge proof.
///
/// Args:
///     public_key: The public key as 32 bytes
///     message: The message as a group element (32 bytes)
///     proof: The proof to verify
///
/// Returns:
///     True if the proof is valid, False otherwise
#[pyfunction]
fn verify_zkp_proof(public_key: &[u8], message: &[u8], proof: &PyProof) -> PyResult<bool> {
    let public_key = GroupElement::from_slice(public_key)
        .ok_or_else(|| PyValueError::new_err("Invalid public key"))?;
    let message = GroupElement::from_slice(message)
        .ok_or_else(|| PyValueError::new_err("Invalid message"))?;

    Ok(verify_proof(&public_key, &message, &proof.inner))
}

/// Register the zkps module.
pub fn register_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let zkps_module = PyModule::new(parent_module.py(), "zkps")?;
    zkps_module.add_class::<PyProof>()?;
    zkps_module.add_function(wrap_pyfunction!(create_zkp_proof, &zkps_module)?)?;
    zkps_module.add_function(wrap_pyfunction!(verify_zkp_proof, &zkps_module)?)?;
    parent_module.add_submodule(&zkps_module)?;
    Ok(())
}
