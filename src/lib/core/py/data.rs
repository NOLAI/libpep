use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::base::py::elgamal::PyElGamal;
use crate::core::data::*;
use crate::core::padding::Padded;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A pseudonym that can be used to identify a user
/// within a specific domain, which can be encrypted, rekeyed and reshuffled.
#[pyclass(name = "Pseudonym")]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyPseudonym(pub(crate) Pseudonym);

#[pymethods]
impl PyPseudonym {
    /// Create from a [`PyGroupElement`].
    #[new]
    fn new(x: PyGroupElement) -> Self {
        Self(Pseudonym::from_point(x.0))
    }

    /// Convert to a [`PyGroupElement`].
    #[pyo3(name = "to_point")]
    fn to_point(&self) -> PyGroupElement {
        self.0.value.into()
    }

    /// Generate a random pseudonym.
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> Self {
        let mut rng = rand::rng();
        Self(Pseudonym::random(&mut rng))
    }

    /// Encode the pseudonym as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Encode the pseudonym as a hexadecimal string.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decode a pseudonym from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        Pseudonym::from_slice(bytes).map(Self)
    }

    /// Decode a pseudonym from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        Pseudonym::from_hex(hex).map(Self)
    }

    /// Decode a pseudonym from a 64-byte hash value
    #[staticmethod]
    #[pyo3(name = "from_hash")]
    fn from_hash(v: &[u8]) -> PyResult<Self> {
        if v.len() != 64 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Hash must be 64 bytes",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(v);
        Ok(Pseudonym::from_hash(&arr).into())
    }

    /// Decode from a byte array of length 16 using lizard encoding.
    /// This is useful for creating a pseudonym from an existing identifier,
    /// as it accepts any 16-byte value.
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
        Ok(Self(Pseudonym::from_lizard(&arr)))
    }

    /// Encode as a byte array of length 16 using lizard encoding.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`PyPseudonym::from_lizard`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[pyo3(name = "to_lizard")]
    fn to_lizard(&self, py: Python) -> Option<Py<PyAny>> {
        self.0.to_lizard().map(|x| PyBytes::new(py, &x).into())
    }

    /// Encodes a byte array (up to 15 bytes) into a `Pseudonym` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> PyResult<Self> {
        Pseudonym::from_bytes_padded(data)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Encodes a string (up to 15 bytes) into a `Pseudonym` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_string_padded")]
    fn from_string_padded(text: &str) -> PyResult<Self> {
        Pseudonym::from_string_padded(text)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Decodes the `Pseudonym` back to the original string.
    #[pyo3(name = "to_string_padded")]
    fn to_string_padded(&self) -> PyResult<String> {
        self.0
            .to_string_padded()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
    }

    /// Decodes the `Pseudonym` back to the original byte array.
    #[pyo3(name = "to_bytes_padded")]
    fn to_bytes_padded(&self, py: Python) -> PyResult<Py<PyAny>> {
        let result = self.0.to_bytes_padded().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
        })?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn __repr__(&self) -> String {
        format!("Pseudonym({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyPseudonym) -> bool {
        self.0 == other.0
    }
}

/// An attribute which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[pyclass(name = "Attribute")]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyAttribute(pub(crate) Attribute);

#[pymethods]
impl PyAttribute {
    /// Create from a [`PyGroupElement`].
    #[new]
    fn new(x: PyGroupElement) -> Self {
        Self(Attribute::from_point(x.0))
    }

    /// Convert to a [`PyGroupElement`].
    #[pyo3(name = "to_point")]
    fn to_point(&self) -> PyGroupElement {
        self.0.value.into()
    }

    /// Generate a random attribute.
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> Self {
        let mut rng = rand::rng();
        Self(Attribute::random(&mut rng))
    }

    /// Encode the attribute as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Encode the attribute as a hexadecimal string.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decode an attribute from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        Attribute::from_slice(bytes).map(Self)
    }

    /// Decode an attribute from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        Attribute::from_hex(hex).map(Self)
    }

    /// Decode an attribute from a 64-byte hash value
    #[staticmethod]
    #[pyo3(name = "from_hash")]
    fn from_hash(v: &[u8]) -> PyResult<Self> {
        if v.len() != 64 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Hash must be 64 bytes",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(v);
        Ok(Attribute::from_hash(&arr).into())
    }

    /// Decode from a byte array of length 16 using lizard encoding.
    /// This is useful for encoding attributes,
    /// as it accepts any 16-byte value.
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
        Ok(Self(Attribute::from_lizard(&arr)))
    }

    /// Encode as a byte array of length 16 using lizard encoding.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`PyAttribute::from_lizard`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[pyo3(name = "to_lizard")]
    fn to_lizard(&self, py: Python) -> Option<Py<PyAny>> {
        self.0.to_lizard().map(|x| PyBytes::new(py, &x).into())
    }

    /// Encodes a byte array (up to 15 bytes) into an `Attribute` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> PyResult<Self> {
        Attribute::from_bytes_padded(data)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Encodes a string (up to 15 bytes) into an `Attribute` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_string_padded")]
    fn from_string_padded(text: &str) -> PyResult<Self> {
        Attribute::from_string_padded(text)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Decodes the `Attribute` back to the original string.
    #[pyo3(name = "to_string_padded")]
    fn to_string_padded(&self) -> PyResult<String> {
        self.0
            .to_string_padded()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
    }

    /// Decodes the `Attribute` back to the original byte array.
    #[pyo3(name = "to_bytes_padded")]
    fn to_bytes_padded(&self, py: Python) -> PyResult<Py<PyAny>> {
        let result = self.0.to_bytes_padded().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
        })?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn __repr__(&self) -> String {
        format!("Attribute({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyAttribute) -> bool {
        self.0 == other.0
    }
}

/// An encrypted pseudonym, which is an [`PyElGamal`] encryption of a [`PyPseudonym`].
#[pyclass(name = "EncryptedPseudonym")]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyEncryptedPseudonym(pub(crate) EncryptedPseudonym);

#[pymethods]
impl PyEncryptedPseudonym {
    /// Create from an [`PyElGamal`].
    #[new]
    fn new(x: PyElGamal) -> Self {
        Self(EncryptedPseudonym::from(x.0))
    }

    /// Encode the encrypted pseudonym as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Decode an encrypted pseudonym from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(v: &[u8]) -> Option<Self> {
        EncryptedPseudonym::from_slice(v).map(Self)
    }

    /// Encode the encrypted pseudonym as a base64 string.
    #[pyo3(name = "to_base64")]
    fn as_base64(&self) -> String {
        self.to_base64()
    }

    /// Decode an encrypted pseudonym from a base64 string.
    #[staticmethod]
    #[pyo3(name = "from_base64")]
    fn from_base64(s: &str) -> Option<Self> {
        EncryptedPseudonym::from_base64(s).map(Self)
    }

    fn __repr__(&self) -> String {
        format!("EncryptedPseudonym({})", self.to_base64())
    }

    fn __str__(&self) -> String {
        self.to_base64()
    }

    fn __eq__(&self, other: &PyEncryptedPseudonym) -> bool {
        self.0 == other.0
    }
}

/// An encrypted attribute, which is an [`PyElGamal`] encryption of a [`PyAttribute`].
#[pyclass(name = "EncryptedAttribute")]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyEncryptedAttribute(pub(crate) EncryptedAttribute);

#[pymethods]
impl PyEncryptedAttribute {
    /// Create from an [`PyElGamal`].
    #[new]
    fn new(x: PyElGamal) -> Self {
        Self(EncryptedAttribute::from(x.0))
    }

    /// Encode the encrypted attribute as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Decode an encrypted attribute from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(v: &[u8]) -> Option<Self> {
        EncryptedAttribute::from_slice(v).map(Self)
    }

    /// Encode the encrypted attribute as a base64 string.
    #[pyo3(name = "to_base64")]
    fn as_base64(&self) -> String {
        self.to_base64()
    }

    /// Decode an encrypted attribute from a base64 string.
    #[staticmethod]
    #[pyo3(name = "from_base64")]
    fn from_base64(s: &str) -> Option<Self> {
        EncryptedAttribute::from_base64(s).map(Self)
    }

    fn __repr__(&self) -> String {
        format!("EncryptedAttribute({})", self.to_base64())
    }

    fn __str__(&self) -> String {
        self.to_base64()
    }

    fn __eq__(&self, other: &PyEncryptedAttribute) -> bool {
        self.0 == other.0
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonym>()?;
    m.add_class::<PyAttribute>()?;
    m.add_class::<PyEncryptedPseudonym>()?;
    m.add_class::<PyEncryptedAttribute>()?;
    Ok(())
}
