use super::super::data::{
    decrypt_long_attribute, decrypt_long_pseudonym, encrypt_long_attribute, encrypt_long_pseudonym,
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use crate::core::data::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::core::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use crate::core::py::data::{PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym};
use crate::core::py::keys::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey,
};
use derive_more::{Deref, From};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A collection of pseudonyms that together represent a larger pseudonym value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// The length (number of blocks) of a `LongPseudonym` may reveal information about the original data.
/// Consider padding your data to a fixed size before encoding to prevent length-based information leakage.
#[pyclass(name = "LongPseudonym")]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongPseudonym(pub(crate) LongPseudonym);

#[pymethods]
impl PyLongPseudonym {
    /// Create from a vector of pseudonyms.
    #[new]
    fn new(pseudonyms: Vec<PyPseudonym>) -> Self {
        let rust_pseudonyms: Vec<Pseudonym> = pseudonyms.into_iter().map(|p| p.0).collect();
        Self(LongPseudonym(rust_pseudonyms))
    }

    /// Encodes an arbitrary-length string into a `LongPseudonym` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_string_padded")]
    fn from_string_padded(text: &str) -> Self {
        Self(LongPseudonym::from_string_padded(text))
    }

    /// Encodes an arbitrary-length byte array into a `LongPseudonym` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> Self {
        Self(LongPseudonym::from_bytes_padded(data))
    }

    /// Decodes the `LongPseudonym` back to the original string.
    #[pyo3(name = "to_string_padded")]
    fn to_string_padded(&self) -> PyResult<String> {
        self.0
            .to_string_padded()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
    }

    /// Decodes the `LongPseudonym` back to the original byte array.
    #[pyo3(name = "to_bytes_padded")]
    fn to_bytes_padded(&self, py: Python) -> PyResult<Py<PyAny>> {
        let result = self.0.to_bytes_padded().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
        })?;
        Ok(PyBytes::new(py, &result).into())
    }

    /// Get the underlying pseudonyms.
    #[pyo3(name = "pseudonyms")]
    fn pseudonyms(&self) -> Vec<PyPseudonym> {
        self.0 .0.iter().map(|p| PyPseudonym(*p)).collect()
    }

    /// Get the number of pseudonym blocks.
    fn __len__(&self) -> usize {
        self.0 .0.len()
    }

    fn __repr__(&self) -> String {
        format!("LongPseudonym({} blocks)", self.0 .0.len())
    }

    fn __eq__(&self, other: &PyLongPseudonym) -> bool {
        self.0 == other.0
    }
}

/// A collection of attributes that together represent a larger data value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// The length (number of blocks) of a `LongAttribute` may reveal information about the original data.
/// Consider padding your data to a fixed size before encoding to prevent length-based information leakage.
#[pyclass(name = "LongAttribute")]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongAttribute(pub(crate) LongAttribute);

#[pymethods]
impl PyLongAttribute {
    /// Create from a vector of attributes.
    #[new]
    fn new(attributes: Vec<PyAttribute>) -> Self {
        let rust_attributes: Vec<Attribute> = attributes.into_iter().map(|a| a.0).collect();
        Self(LongAttribute(rust_attributes))
    }

    /// Encodes an arbitrary-length string into a `LongAttribute` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_string_padded")]
    fn from_string_padded(text: &str) -> Self {
        Self(LongAttribute::from_string_padded(text))
    }

    /// Encodes an arbitrary-length byte array into a `LongAttribute` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> Self {
        Self(LongAttribute::from_bytes_padded(data))
    }

    /// Decodes the `LongAttribute` back to the original string.
    #[pyo3(name = "to_string_padded")]
    fn to_string_padded(&self) -> PyResult<String> {
        self.0
            .to_string_padded()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
    }

    /// Decodes the `LongAttribute` back to the original byte array.
    #[pyo3(name = "to_bytes_padded")]
    fn to_bytes_padded(&self, py: Python) -> PyResult<Py<PyAny>> {
        let result = self.0.to_bytes_padded().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
        })?;
        Ok(PyBytes::new(py, &result).into())
    }

    /// Get the underlying attributes.
    #[pyo3(name = "attributes")]
    fn attributes(&self) -> Vec<PyAttribute> {
        self.0 .0.iter().map(|a| PyAttribute(*a)).collect()
    }

    /// Get the number of attribute blocks.
    fn __len__(&self) -> usize {
        self.0 .0.len()
    }

    fn __repr__(&self) -> String {
        format!("LongAttribute({} blocks)", self.0 .0.len())
    }

    fn __eq__(&self, other: &PyLongAttribute) -> bool {
        self.0 == other.0
    }
}

/// A collection of encrypted pseudonyms that can be serialized as a pipe-delimited string.
#[pyclass(name = "LongEncryptedPseudonym")]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongEncryptedPseudonym(pub(crate) LongEncryptedPseudonym);

#[pymethods]
impl PyLongEncryptedPseudonym {
    /// Create from a vector of encrypted pseudonyms.
    #[new]
    fn new(encrypted_pseudonyms: Vec<PyEncryptedPseudonym>) -> Self {
        let rust_enc_pseudonyms: Vec<EncryptedPseudonym> =
            encrypted_pseudonyms.into_iter().map(|p| p.0).collect();
        Self(LongEncryptedPseudonym(rust_enc_pseudonyms))
    }

    /// Serializes to a pipe-delimited base64 string.
    #[pyo3(name = "serialize")]
    fn serialize(&self) -> String {
        self.0.serialize()
    }

    /// Deserializes from a pipe-delimited base64 string.
    #[staticmethod]
    #[pyo3(name = "deserialize")]
    fn deserialize(s: &str) -> PyResult<Self> {
        LongEncryptedPseudonym::deserialize(s)
            .map(Self)
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Deserialization failed: {e}"))
            })
    }

    /// Get the underlying encrypted pseudonyms.
    #[pyo3(name = "encrypted_pseudonyms")]
    fn encrypted_pseudonyms(&self) -> Vec<PyEncryptedPseudonym> {
        self.0 .0.iter().map(|p| PyEncryptedPseudonym(*p)).collect()
    }

    /// Get the number of encrypted pseudonym blocks.
    fn __len__(&self) -> usize {
        self.0 .0.len()
    }

    fn __repr__(&self) -> String {
        format!("LongEncryptedPseudonym({} blocks)", self.0 .0.len())
    }

    fn __eq__(&self, other: &PyLongEncryptedPseudonym) -> bool {
        self.0 == other.0
    }
}

/// A collection of encrypted attributes that can be serialized as a pipe-delimited string.
#[pyclass(name = "LongEncryptedAttribute")]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongEncryptedAttribute(pub(crate) LongEncryptedAttribute);

#[pymethods]
impl PyLongEncryptedAttribute {
    /// Create from a vector of encrypted attributes.
    #[new]
    fn new(encrypted_attributes: Vec<PyEncryptedAttribute>) -> Self {
        let rust_enc_attributes: Vec<EncryptedAttribute> =
            encrypted_attributes.into_iter().map(|a| a.0).collect();
        Self(LongEncryptedAttribute(rust_enc_attributes))
    }

    /// Serializes to a pipe-delimited base64 string.
    #[pyo3(name = "serialize")]
    fn serialize(&self) -> String {
        self.0.serialize()
    }

    /// Deserializes from a pipe-delimited base64 string.
    #[staticmethod]
    #[pyo3(name = "deserialize")]
    fn deserialize(s: &str) -> PyResult<Self> {
        LongEncryptedAttribute::deserialize(s)
            .map(Self)
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Deserialization failed: {e}"))
            })
    }

    /// Get the underlying encrypted attributes.
    #[pyo3(name = "encrypted_attributes")]
    fn encrypted_attributes(&self) -> Vec<PyEncryptedAttribute> {
        self.0 .0.iter().map(|a| PyEncryptedAttribute(*a)).collect()
    }

    /// Get the number of encrypted attribute blocks.
    fn __len__(&self) -> usize {
        self.0 .0.len()
    }

    fn __repr__(&self) -> String {
        format!("LongEncryptedAttribute({} blocks)", self.0 .0.len())
    }

    fn __eq__(&self, other: &PyLongEncryptedAttribute) -> bool {
        self.0 == other.0
    }
}

/// Encrypt a long pseudonym.
#[pyfunction]
#[pyo3(name = "encrypt_long_pseudonym")]
pub fn py_encrypt_long_pseudonym(
    message: &PyLongPseudonym,
    public_key: &PyPseudonymSessionPublicKey,
) -> PyLongEncryptedPseudonym {
    let mut rng = rand::rng();
    PyLongEncryptedPseudonym(encrypt_long_pseudonym(
        &message.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt a long encrypted pseudonym.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_long_pseudonym")]
pub fn py_decrypt_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
    secret_key: &PyPseudonymSessionSecretKey,
) -> Option<PyLongPseudonym> {
    decrypt_long_pseudonym(
        &encrypted.0,
        &PseudonymSessionSecretKey::from(secret_key.0 .0),
    )
    .map(PyLongPseudonym)
}

/// Decrypt a long encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_long_pseudonym")]
pub fn py_decrypt_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
    secret_key: &PyPseudonymSessionSecretKey,
) -> PyLongPseudonym {
    PyLongPseudonym(decrypt_long_pseudonym(
        &encrypted.0,
        &PseudonymSessionSecretKey::from(secret_key.0 .0),
    ))
}

/// Encrypt a long attribute.
#[pyfunction]
#[pyo3(name = "encrypt_long_attribute")]
pub fn py_encrypt_long_attribute(
    message: &PyLongAttribute,
    public_key: &PyAttributeSessionPublicKey,
) -> PyLongEncryptedAttribute {
    let mut rng = rand::rng();
    PyLongEncryptedAttribute(encrypt_long_attribute(
        &message.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt a long encrypted attribute.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_long_attribute")]
pub fn py_decrypt_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
    secret_key: &PyAttributeSessionSecretKey,
) -> Option<PyLongAttribute> {
    decrypt_long_attribute(
        &encrypted.0,
        &AttributeSessionSecretKey::from(secret_key.0 .0),
    )
    .map(PyLongAttribute)
}

/// Decrypt a long encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_long_attribute")]
pub fn py_decrypt_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
    secret_key: &PyAttributeSessionSecretKey,
) -> PyLongAttribute {
    PyLongAttribute(decrypt_long_attribute(
        &encrypted.0,
        &AttributeSessionSecretKey::from(secret_key.0 .0),
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyLongPseudonym>()?;
    m.add_class::<PyLongAttribute>()?;
    m.add_class::<PyLongEncryptedPseudonym>()?;
    m.add_class::<PyLongEncryptedAttribute>()?;
    m.add_function(wrap_pyfunction!(py_encrypt_long_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_long_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_long_attribute, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_long_attribute, m)?)?;
    Ok(())
}
