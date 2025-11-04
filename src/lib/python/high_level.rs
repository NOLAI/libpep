use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::high_level::padding::{LongAttribute, LongPseudonym, Padded};
use crate::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::internal::arithmetic::GroupElement;
use crate::python::arithmetic::{PyGroupElement, PyScalarNonZero};
use crate::python::elgamal::PyElGamal;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A pseudonym session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymSessionSecretKey")]
pub struct PyPseudonymSessionSecretKey(pub PyScalarNonZero);

/// An attribute session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeSessionSecretKey")]
pub struct PyAttributeSessionSecretKey(pub PyScalarNonZero);

/// A pseudonym global secret key from which pseudonym session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[pyclass(name = "PseudonymGlobalSecretKey")]
pub struct PyPseudonymGlobalSecretKey(pub PyScalarNonZero);

/// An attribute global secret key from which attribute session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[pyclass(name = "AttributeGlobalSecretKey")]
pub struct PyAttributeGlobalSecretKey(pub PyScalarNonZero);

/// A pseudonym session public key used to encrypt pseudonyms against.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymSessionPublicKey")]
pub struct PyPseudonymSessionPublicKey(pub PyGroupElement);

#[pymethods]
impl PyPseudonymSessionPublicKey {
    /// Returns the group element associated with this public key.
    #[pyo3(name = "to_point")]
    fn to_point(&self) -> PyGroupElement {
        self.0
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
}

/// An attribute session public key used to encrypt attributes against.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeSessionPublicKey")]
pub struct PyAttributeSessionPublicKey(pub PyGroupElement);

#[pymethods]
impl PyAttributeSessionPublicKey {
    /// Returns the group element associated with this public key.
    #[pyo3(name = "to_point")]
    fn to_point(&self) -> PyGroupElement {
        self.0
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
}

/// A pseudonym global public key from which pseudonym session keys are derived.
/// Can also be used to encrypt pseudonyms against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, PartialEq, Eq, From)]
#[pyclass(name = "PseudonymGlobalPublicKey")]
pub struct PyPseudonymGlobalPublicKey(pub PyGroupElement);

#[pymethods]
impl PyPseudonymGlobalPublicKey {
    /// Creates a new pseudonym global public key from a group element.
    #[new]
    fn new(x: PyGroupElement) -> Self {
        Self(x.0.into())
    }

    /// Returns the group element associated with this public key.
    #[pyo3(name = "to_point")]
    fn to_point(&self) -> PyGroupElement {
        self.0
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decodes a public key from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        let x = GroupElement::decode_from_hex(hex)?;
        Some(Self(x.into()))
    }

    fn __repr__(&self) -> String {
        format!("PseudonymGlobalPublicKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }
}

/// An attribute global public key from which attribute session keys are derived.
/// Can also be used to encrypt attributes against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, PartialEq, Eq, From)]
#[pyclass(name = "AttributeGlobalPublicKey")]
pub struct PyAttributeGlobalPublicKey(pub PyGroupElement);

#[pymethods]
impl PyAttributeGlobalPublicKey {
    /// Creates a new attribute global public key from a group element.
    #[new]
    fn new(x: PyGroupElement) -> Self {
        Self(x.0.into())
    }

    /// Returns the group element associated with this public key.
    #[pyo3(name = "to_point")]
    fn to_point(&self) -> PyGroupElement {
        self.0
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decodes a public key from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        let x = GroupElement::decode_from_hex(hex)?;
        Some(Self(x.into()))
    }

    fn __repr__(&self) -> String {
        format!("AttributeGlobalPublicKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }
}

/// A pair of global public keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[pyclass(name = "GlobalPublicKeys")]
pub struct PyGlobalPublicKeys {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymGlobalPublicKey,
    #[pyo3(get)]
    pub attribute: PyAttributeGlobalPublicKey,
}

#[pymethods]
impl PyGlobalPublicKeys {
    /// Create new global public keys from pseudonym and attribute keys.
    #[new]
    fn new(pseudonym: PyPseudonymGlobalPublicKey, attribute: PyAttributeGlobalPublicKey) -> Self {
        PyGlobalPublicKeys {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "GlobalPublicKeys(pseudonym={}, attribute={})",
            self.pseudonym.as_hex(),
            self.attribute.as_hex()
        )
    }

    fn __eq__(&self, other: &PyGlobalPublicKeys) -> bool {
        self.pseudonym.0 == other.pseudonym.0 && self.attribute.0 == other.attribute.0
    }
}

/// A pair of global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Debug)]
#[pyclass(name = "GlobalSecretKeys")]
pub struct PyGlobalSecretKeys {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymGlobalSecretKey,
    #[pyo3(get)]
    pub attribute: PyAttributeGlobalSecretKey,
}

#[pymethods]
impl PyGlobalSecretKeys {
    /// Create new global secret keys from pseudonym and attribute keys.
    #[new]
    fn new(pseudonym: PyPseudonymGlobalSecretKey, attribute: PyAttributeGlobalSecretKey) -> Self {
        PyGlobalSecretKeys {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        "GlobalSecretKeys(pseudonym=..., attribute=...)".to_string()
    }
}

/// Pseudonymization secret used to derive a [`PyReshuffleFactor`] from a pseudonymization domain (see [`PyPseudonymizationInfo`]).
/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from domains and sessions.
#[derive(Clone, Debug, From)]
#[pyclass(name = "PseudonymizationSecret")]
pub struct PyPseudonymizationSecret(pub(crate) PseudonymizationSecret);

/// Encryption secret used to derive rekey factors from an encryption context (see [`PyPseudonymRekeyInfo`] and [`PyAttributeRekeyInfo`]).
/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from domains and sessions.
#[derive(Clone, Debug, From)]
#[pyclass(name = "EncryptionSecret")]
pub struct PyEncryptionSecret(pub(crate) EncryptionSecret);

#[pymethods]
impl PyPseudonymizationSecret {
    #[new]
    fn new(data: Vec<u8>) -> Self {
        Self(PseudonymizationSecret::from(data))
    }
}

#[pymethods]
impl PyEncryptionSecret {
    #[new]
    fn new(data: Vec<u8>) -> Self {
        Self(EncryptionSecret::from(data))
    }
}

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
        let mut rng = rand::thread_rng();
        Self(Pseudonym::random(&mut rng))
    }

    /// Encode the pseudonym as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Encode the pseudonym as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a pseudonym from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        Pseudonym::decode_from_slice(bytes).map(Self)
    }

    /// Decode a pseudonym from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        Pseudonym::decode_from_hex(hex).map(Self)
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

    /// Decode from a byte array of length 16.
    /// This is useful for creating a pseudonym from an existing identifier,
    /// as it accepts any 16-byte value.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        if data.len() != 16 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Data must be 16 bytes",
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(data);
        Ok(Self(Pseudonym::from_bytes(&arr)))
    }

    /// Encode as a byte array of length 16.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`PyPseudonym::from_bytes`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[pyo3(name = "as_bytes")]
    fn as_bytes(&self, py: Python) -> Option<Py<PyAny>> {
        self.0.as_bytes().map(|x| PyBytes::new(py, &x).into())
    }

    /// Encodes a byte array (up to 16 bytes) into a `Pseudonym` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> PyResult<Self> {
        Pseudonym::from_bytes_padded(data)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Encodes a string (up to 16 bytes) into a `Pseudonym` using PKCS#7 padding.
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
        let mut rng = rand::thread_rng();
        Self(Attribute::random(&mut rng))
    }

    /// Encode the attribute as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Encode the attribute as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode an attribute from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        Attribute::decode_from_slice(bytes).map(Self)
    }

    /// Decode an attribute from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        Attribute::decode_from_hex(hex).map(Self)
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

    /// Decode from a byte array of length 16.
    /// This is useful for encoding attributes,
    /// as it accepts any 16-byte value.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        if data.len() != 16 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Data must be 16 bytes",
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(data);
        Ok(Self(Attribute::from_bytes(&arr)))
    }

    /// Encode as a byte array of length 16.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`PyAttribute::from_bytes`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[pyo3(name = "as_bytes")]
    fn as_bytes(&self, py: Python) -> Option<Py<PyAny>> {
        self.0.as_bytes().map(|x| PyBytes::new(py, &x).into())
    }

    /// Encodes a byte array (up to 16 bytes) into an `Attribute` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> PyResult<Self> {
        Attribute::from_bytes_padded(data)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Encodes a string (up to 16 bytes) into an `Attribute` using PKCS#7 padding.
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
    fn from_string_padded(text: &str) -> PyResult<Self> {
        LongPseudonym::from_string_padded(text)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Encodes an arbitrary-length byte array into a `LongPseudonym` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> PyResult<Self> {
        LongPseudonym::from_bytes_padded(data)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
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
    fn from_string_padded(text: &str) -> PyResult<Self> {
        LongAttribute::from_string_padded(text)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
    }

    /// Encodes an arbitrary-length byte array into a `LongAttribute` using PKCS#7 padding.
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> PyResult<Self> {
        LongAttribute::from_bytes_padded(data)
            .map(Self)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}")))
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
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decode an encrypted pseudonym from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(v: &[u8]) -> Option<Self> {
        EncryptedPseudonym::decode_from_slice(v).map(Self)
    }

    /// Encode the encrypted pseudonym as a base64 string.
    #[pyo3(name = "as_base64")]
    fn as_base64(&self) -> String {
        self.encode_as_base64()
    }

    /// Decode an encrypted pseudonym from a base64 string.
    #[staticmethod]
    #[pyo3(name = "from_base64")]
    fn from_base64(s: &str) -> Option<Self> {
        EncryptedPseudonym::from_base64(s).map(Self)
    }

    fn __repr__(&self) -> String {
        format!("EncryptedPseudonym({})", self.as_base64())
    }

    fn __str__(&self) -> String {
        self.as_base64()
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
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decode an encrypted attribute from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(v: &[u8]) -> Option<Self> {
        EncryptedAttribute::decode_from_slice(v).map(Self)
    }

    /// Encode the encrypted attribute as a base64 string.
    #[pyo3(name = "as_base64")]
    fn as_base64(&self) -> String {
        self.encode_as_base64()
    }

    /// Decode an encrypted attribute from a base64 string.
    #[staticmethod]
    #[pyo3(name = "from_base64")]
    fn from_base64(s: &str) -> Option<Self> {
        EncryptedAttribute::from_base64(s).map(Self)
    }

    fn __repr__(&self) -> String {
        format!("EncryptedAttribute({})", self.as_base64())
    }

    fn __str__(&self) -> String {
        self.as_base64()
    }

    fn __eq__(&self, other: &PyEncryptedAttribute) -> bool {
        self.0 == other.0
    }
}

// Pseudonym global key pair
#[pyclass(name = "PseudonymGlobalKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PyPseudonymGlobalKeyPair {
    #[pyo3(get)]
    pub public: PyPseudonymGlobalPublicKey,
    #[pyo3(get)]
    pub secret: PyPseudonymGlobalSecretKey,
}

// Attribute global key pair
#[pyclass(name = "AttributeGlobalKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PyAttributeGlobalKeyPair {
    #[pyo3(get)]
    pub public: PyAttributeGlobalPublicKey,
    #[pyo3(get)]
    pub secret: PyAttributeGlobalSecretKey,
}

// Pseudonym session key pair
#[pyclass(name = "PseudonymSessionKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PyPseudonymSessionKeyPair {
    #[pyo3(get)]
    pub public: PyPseudonymSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyPseudonymSessionSecretKey,
}

// Attribute session key pair
#[pyclass(name = "AttributeSessionKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PyAttributeSessionKeyPair {
    #[pyo3(get)]
    pub public: PyAttributeSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyAttributeSessionSecretKey,
}

/// Generate a new pseudonym global key pair.
#[pyfunction]
#[pyo3(name = "make_pseudonym_global_keys")]
pub fn py_make_pseudonym_global_keys() -> PyPseudonymGlobalKeyPair {
    let mut rng = rand::thread_rng();
    let (public, secret) = make_pseudonym_global_keys(&mut rng);
    PyPseudonymGlobalKeyPair {
        public: PyPseudonymGlobalPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyPseudonymGlobalSecretKey::from(PyScalarNonZero::from(secret.0)),
    }
}

/// Generate a new attribute global key pair.
#[pyfunction]
#[pyo3(name = "make_attribute_global_keys")]
pub fn py_make_attribute_global_keys() -> PyAttributeGlobalKeyPair {
    let mut rng = rand::thread_rng();
    let (public, secret) = make_attribute_global_keys(&mut rng);
    PyAttributeGlobalKeyPair {
        public: PyAttributeGlobalPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyAttributeGlobalSecretKey::from(PyScalarNonZero::from(secret.0)),
    }
}

/// Generate pseudonym session keys from a [`PyPseudonymGlobalSecretKey`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_keys")]
pub fn py_make_pseudonym_session_keys(
    global: &PyPseudonymGlobalSecretKey,
    session: &str,
    secret: &PyEncryptionSecret,
) -> PyPseudonymSessionKeyPair {
    let (public, secret_key) = make_pseudonym_session_keys(
        &PseudonymGlobalSecretKey(global.0 .0),
        &EncryptionContext::from(session),
        &secret.0,
    );
    PyPseudonymSessionKeyPair {
        public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(secret_key.0)),
    }
}

/// Generate attribute session keys from a [`PyAttributeGlobalSecretKey`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_attribute_session_keys")]
pub fn py_make_attribute_session_keys(
    global: &PyAttributeGlobalSecretKey,
    session: &str,
    secret: &PyEncryptionSecret,
) -> PyAttributeSessionKeyPair {
    let (public, secret_key) = make_attribute_session_keys(
        &AttributeGlobalSecretKey(global.0 .0),
        &EncryptionContext::from(session),
        &secret.0,
    );
    PyAttributeSessionKeyPair {
        public: PyAttributeSessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(secret_key.0)),
    }
}

/// Encrypt a pseudonym using a pseudonym session public key.
#[pyfunction]
#[pyo3(name = "encrypt_pseudonym")]
pub fn py_encrypt_pseudonym(
    message: &PyPseudonym,
    public_key: &PyPseudonymSessionPublicKey,
) -> PyEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    PyEncryptedPseudonym(encrypt_pseudonym(
        &message.0,
        &PseudonymSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt an encrypted pseudonym using a pseudonym session secret key.
#[pyfunction]
#[pyo3(name = "decrypt_pseudonym")]
pub fn py_decrypt_pseudonym(
    encrypted: &PyEncryptedPseudonym,
    secret_key: &PyPseudonymSessionSecretKey,
) -> PyPseudonym {
    PyPseudonym(decrypt_pseudonym(
        &encrypted.0,
        &PseudonymSessionSecretKey::from(secret_key.0 .0),
    ))
}

/// Encrypt an attribute using an attribute session public key.
#[pyfunction]
#[pyo3(name = "encrypt_data")]
pub fn py_encrypt_data(
    message: &PyAttribute,
    public_key: &PyAttributeSessionPublicKey,
) -> PyEncryptedAttribute {
    let mut rng = rand::thread_rng();
    PyEncryptedAttribute(encrypt_attribute(
        &message.0,
        &AttributeSessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt an encrypted attribute using an attribute session secret key.
#[pyfunction]
#[pyo3(name = "decrypt_data")]
pub fn py_decrypt_data(
    encrypted: &PyEncryptedAttribute,
    secret_key: &PyAttributeSessionSecretKey,
) -> PyAttribute {
    PyAttribute(decrypt_attribute(
        &EncryptedAttribute::from(encrypted.value),
        &AttributeSessionSecretKey::from(secret_key.0 .0),
    ))
}

/// Generate new global key pairs for both pseudonyms and attributes.
#[pyfunction]
#[pyo3(name = "make_global_keys")]
pub fn py_make_global_keys() -> (PyGlobalPublicKeys, PyGlobalSecretKeys) {
    let mut rng = rand::thread_rng();
    let (public, secret) = make_global_keys(&mut rng);
    (
        PyGlobalPublicKeys {
            pseudonym: PyPseudonymGlobalPublicKey::from(PyGroupElement::from(public.pseudonym.0)),
            attribute: PyAttributeGlobalPublicKey::from(PyGroupElement::from(public.attribute.0)),
        },
        PyGlobalSecretKeys {
            pseudonym: PyPseudonymGlobalSecretKey::from(PyScalarNonZero::from(secret.pseudonym.0)),
            attribute: PyAttributeGlobalSecretKey::from(PyScalarNonZero::from(secret.attribute.0)),
        },
    )
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymSessionSecretKey>()?;
    m.add_class::<PyAttributeSessionSecretKey>()?;
    m.add_class::<PyPseudonymGlobalSecretKey>()?;
    m.add_class::<PyAttributeGlobalSecretKey>()?;
    m.add_class::<PyPseudonymSessionPublicKey>()?;
    m.add_class::<PyAttributeSessionPublicKey>()?;
    m.add_class::<PyPseudonymGlobalPublicKey>()?;
    m.add_class::<PyAttributeGlobalPublicKey>()?;
    m.add_class::<PyGlobalPublicKeys>()?;
    m.add_class::<PyGlobalSecretKeys>()?;
    m.add_class::<PyPseudonymizationSecret>()?;
    m.add_class::<PyEncryptionSecret>()?;
    m.add_class::<PyPseudonym>()?;
    m.add_class::<PyAttribute>()?;
    m.add_class::<PyLongPseudonym>()?;
    m.add_class::<PyLongAttribute>()?;
    m.add_class::<PyEncryptedPseudonym>()?;
    m.add_class::<PyEncryptedAttribute>()?;
    m.add_class::<PyPseudonymGlobalKeyPair>()?;
    m.add_class::<PyAttributeGlobalKeyPair>()?;
    m.add_class::<PyPseudonymSessionKeyPair>()?;
    m.add_class::<PyAttributeSessionKeyPair>()?;
    m.add_function(wrap_pyfunction!(py_make_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_data, m)?)?;
    Ok(())
}
