use crate::internal::arithmetic::*;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;
use rand::rngs::OsRng;

/// Element on a group. Can not be converted to a scalar. Supports addition and subtraction. Multiplication by a scalar is supported.
/// We use ristretto points to discard unsafe points and safely use the group operations in higher level protocols without any other cryptographic assumptions.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "GroupElement")]
pub struct PyGroupElement(pub(crate) GroupElement);

#[pymethods]
impl PyGroupElement {
    /// Encodes the group element as a 32-byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decodes a group element from a 32-byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> PyResult<Option<PyGroupElement>> {
        Ok(GroupElement::decode_from_slice(bytes).map(PyGroupElement))
    }

    /// Generates a random group element.
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> PyGroupElement {
        GroupElement::random(&mut OsRng).into()
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
        Ok(GroupElement::decode_from_hash(&arr).into())
    }

    /// Decodes a group element from a hexadecimal string of 64 characters.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyGroupElement> {
        GroupElement::decode_from_hex(hex).map(PyGroupElement)
    }

    /// Encodes the group element as a hexadecimal string of 64 characters.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
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

/// Non-zero scalar. Supports addition, subtraction, multiplication, and inversion. Can be converted to a scalar that can be zero.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "ScalarNonZero")]
pub struct PyScalarNonZero(pub(crate) ScalarNonZero);

#[pymethods]
impl PyScalarNonZero {
    /// Encodes the scalar as a 32-byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decodes a scalar from a 32-byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyScalarNonZero> {
        ScalarNonZero::decode_from_slice(bytes).map(PyScalarNonZero)
    }

    /// Decodes a scalar from a hexadecimal string of 64 characters.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyScalarNonZero> {
        ScalarNonZero::decode_from_hex(hex).map(PyScalarNonZero)
    }

    /// Encodes the scalar as a hexadecimal string of 64 characters.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Generates a random non-zero scalar.
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> PyScalarNonZero {
        ScalarNonZero::random(&mut OsRng).into()
    }

    /// Decodes a scalar from a 64-byte hash.
    #[staticmethod]
    #[pyo3(name = "from_hash")]
    fn from_hash(v: &[u8]) -> PyResult<PyScalarNonZero> {
        if v.len() != 64 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Hash must be 64 bytes",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(v);
        Ok(ScalarNonZero::decode_from_hash(&arr).into())
    }

    /// Returns scalar one.
    #[staticmethod]
    #[pyo3(name = "one")]
    fn one() -> PyScalarNonZero {
        ScalarNonZero::one().into()
    }

    /// Inverts the scalar.
    #[pyo3(name = "invert")]
    fn invert(&self) -> PyScalarNonZero {
        self.0.invert().into()
    }

    /// Multiplies two scalars.
    #[pyo3(name = "mul")]
    fn mul(&self, other: &PyScalarNonZero) -> PyScalarNonZero {
        (self.0 * other.0).into() // Guaranteed to be non-zero
    }

    /// Converts the scalar to a scalar that can be zero.
    #[pyo3(name = "to_can_be_zero")]
    fn to_can_be_zero(&self) -> PyScalarCanBeZero {
        let s: ScalarCanBeZero = self.0.into();
        PyScalarCanBeZero(s)
    }

    fn __mul__(&self, other: &PyScalarNonZero) -> PyScalarNonZero {
        self.mul(other)
    }

    fn __repr__(&self) -> String {
        format!("ScalarNonZero({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyScalarNonZero) -> bool {
        self.0 == other.0
    }
}

/// Scalar that can be zero. Supports addition and subtraction, but not multiplication or inversion.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "ScalarCanBeZero")]
pub struct PyScalarCanBeZero(pub(crate) ScalarCanBeZero);

#[pymethods]
impl PyScalarCanBeZero {
    /// Encodes the scalar as a 32-byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decodes a scalar from a 32-byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyScalarCanBeZero> {
        ScalarCanBeZero::decode_from_slice(bytes).map(PyScalarCanBeZero)
    }

    /// Decodes a scalar from a hexadecimal string of 64 characters.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyScalarCanBeZero> {
        ScalarCanBeZero::decode_from_hex(hex).map(PyScalarCanBeZero)
    }

    /// Encodes the scalar as a hexadecimal string of 64 characters.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Returns scalar one.
    #[staticmethod]
    #[pyo3(name = "one")]
    fn one() -> PyScalarCanBeZero {
        ScalarCanBeZero::one().into()
    }

    /// Returns scalar zero.
    #[staticmethod]
    #[pyo3(name = "zero")]
    fn zero() -> PyScalarCanBeZero {
        ScalarCanBeZero::zero().into()
    }

    /// Checks if the scalar is zero.
    #[pyo3(name = "is_zero")]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Adds two scalars.
    #[pyo3(name = "add")]
    fn add(&self, other: &PyScalarCanBeZero) -> PyScalarCanBeZero {
        (self.0 + other.0).into()
    }

    /// Subtracts two scalars.
    #[pyo3(name = "sub")]
    fn sub(&self, other: &PyScalarCanBeZero) -> PyScalarCanBeZero {
        (self.0 - other.0).into()
    }

    /// Tries to convert the scalar to a scalar that can not be zero.
    #[pyo3(name = "to_non_zero")]
    fn to_non_zero(&self) -> Option<PyScalarNonZero> {
        let s: ScalarNonZero = self.0.try_into().ok()?;
        Some(PyScalarNonZero(s))
    }

    fn __add__(&self, other: &PyScalarCanBeZero) -> PyScalarCanBeZero {
        self.add(other)
    }

    fn __sub__(&self, other: &PyScalarCanBeZero) -> PyScalarCanBeZero {
        self.sub(other)
    }

    fn __repr__(&self) -> String {
        format!("ScalarCanBeZero({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyScalarCanBeZero) -> bool {
        self.0 == other.0
    }
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyGroupElement>()?;
    m.add_class::<PyScalarNonZero>()?;
    m.add_class::<PyScalarCanBeZero>()?;
    Ok(())
}
