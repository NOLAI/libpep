use crate::arithmetic::py::{PyGroupElement, PyScalarNonZero};
use crate::base::elgamal::{decrypt, encrypt, ElGamal};
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;
/// An ElGamal ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "ElGamal")]
pub struct PyElGamal(pub(crate) ElGamal);

#[pymethods]
impl PyElGamal {
    /// Encodes the ElGamal ciphertext as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Decodes an ElGamal ciphertext from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(v: &[u8]) -> Option<PyElGamal> {
        ElGamal::from_slice(v).map(PyElGamal)
    }

    /// Encodes the ElGamal ciphertext as a base64 string.
    #[pyo3(name = "to_base64")]
    fn as_base64(&self) -> String {
        self.0.to_base64()
    }

    /// Decodes an ElGamal ciphertext from a base64 string.
    #[staticmethod]
    #[pyo3(name = "from_base64")]
    fn from_base64(s: &str) -> Option<PyElGamal> {
        ElGamal::from_base64(s).map(PyElGamal)
    }

    fn __repr__(&self) -> String {
        format!("ElGamal({})", self.to_base64())
    }

    fn __str__(&self) -> String {
        self.to_base64()
    }

    fn __eq__(&self, other: &PyElGamal) -> bool {
        self.0 == other.0
    }
}

/// Encrypts a message (group element) using the ElGamal encryption scheme.
#[pyfunction]
#[pyo3(name = "encrypt")]
pub fn encrypt_py(gm: &PyGroupElement, gy: &PyGroupElement) -> PyElGamal {
    let mut rng = rand::rng();
    encrypt(&gm.0, &gy.0, &mut rng).into()
}

/// Decrypts an ElGamal ciphertext using the provided secret key and returns the group element.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
#[pyfunction]
#[pyo3(name = "decrypt")]
#[cfg(feature = "elgamal3")]
pub fn decrypt_py(encrypted: &PyElGamal, y: &PyScalarNonZero) -> Option<PyGroupElement> {
    decrypt(&encrypted.0, &y.0).map(|x| x.into())
}

/// Decrypts an ElGamal ciphertext using the provided secret key and returns the group element.
#[pyfunction]
#[pyo3(name = "decrypt")]
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt_py(encrypted: &PyElGamal, y: &PyScalarNonZero) -> PyGroupElement {
    decrypt(&encrypted.0, &y.0).into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyElGamal>()?;
    m.add_function(wrap_pyfunction!(encrypt_py, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_py, m)?)?;
    Ok(())
}
