use super::super::group_elements::{GroupElement, G};
use crate::arithmetic::py::PyScalarNonZero;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// Element on a group. Can not be converted to a scalar. Supports addition and subtraction. Multiplication by a scalar is supported.
/// We use ristretto points to discard unsafe points and safely use the group operations in higher level protocols without any other cryptographic assumptions.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "GroupElement")]
pub struct PyGroupElement(pub(crate) GroupElement);

#[pymethods]
impl PyGroupElement {
    /// Encodes the group element as a 32-byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Decodes a group element from a 32-byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> PyResult<Option<PyGroupElement>> {
        Ok(GroupElement::from_slice(bytes).map(PyGroupElement))
    }

    /// Generates a random group element.
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> PyGroupElement {
        GroupElement::random(&mut rand::rng()).into()
    }

    /// Decodes a group element from a 64-byte hash.
    #[staticmethod]
    #[pyo3(name = "from_hash")]
    fn from_hash(v: &[u8]) -> PyResult<PyGroupElement> {
        if v.len() != 64 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Hash must be 64 bytes",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(v);
        Ok(GroupElement::from_hash(&arr).into())
    }

    /// Decodes a group element from a hexadecimal string of 64 characters.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyGroupElement> {
        GroupElement::from_hex(hex).map(PyGroupElement)
    }

    /// Encodes the group element as a hexadecimal string of 64 characters.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decode from a byte array of length 16 using lizard encoding.
    #[staticmethod]
    #[pyo3(name = "from_lizard")]
    fn from_lizard(data: &[u8]) -> PyResult<Self> {
        if data.len() != 16 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Data must be 16 bytes",
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(data);
        Ok(Self(GroupElement::from_lizard(&arr)))
    }

    /// Encode as a byte array of length 16 using lizard encoding.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    #[pyo3(name = "to_lizard")]
    fn encode_lizard(&self, py: Python) -> Option<Py<PyAny>> {
        self.0.to_lizard().map(|x| PyBytes::new(py, &x).into())
    }

    /// Returns the identity element of the group.
    #[staticmethod]
    #[pyo3(name = "identity")]
    fn identity() -> PyGroupElement {
        GroupElement::identity().into()
    }

    /// Returns the generator of the group.
    #[staticmethod]
    #[pyo3(name = "generator")]
    fn generator() -> PyGroupElement {
        G.into()
    }

    /// Adds two group elements.
    #[pyo3(name = "add")]
    fn add(&self, other: &PyGroupElement) -> PyGroupElement {
        PyGroupElement(self.0 + other.0)
    }

    /// Subtracts two group elements.
    #[pyo3(name = "sub")]
    fn sub(&self, other: &PyGroupElement) -> PyGroupElement {
        PyGroupElement(self.0 - other.0)
    }

    /// Multiplies a group element by a scalar.
    #[pyo3(name = "mul")]
    fn mul(&self, other: &PyScalarNonZero) -> PyGroupElement {
        (other.0 * self.0).into() // Only possible if the scalar is non-zero
    }

    fn __add__(&self, other: &PyGroupElement) -> PyGroupElement {
        self.add(other)
    }

    fn __sub__(&self, other: &PyGroupElement) -> PyGroupElement {
        self.sub(other)
    }

    fn __mul__(&self, other: &PyScalarNonZero) -> PyGroupElement {
        self.mul(other)
    }

    fn __repr__(&self) -> String {
        format!("GroupElement({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyGroupElement) -> bool {
        self.0 == other.0
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyGroupElement>()?;
    Ok(())
}
