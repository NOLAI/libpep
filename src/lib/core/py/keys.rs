use super::super::keys::*;
use super::super::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::arithmetic::py::scalars::PyScalarNonZero;
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

    /// Encodes the public key as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0 .0.to_bytes()).into()
    }

    /// Decodes a public key from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        GroupElement::from_slice(bytes).map(|x| Self(x.into()))
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decodes a public key from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        GroupElement::from_hex(hex).map(|x| Self(x.into()))
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

    /// Encodes the public key as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0 .0.to_bytes()).into()
    }

    /// Decodes a public key from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        GroupElement::from_slice(bytes).map(|x| Self(x.into()))
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decodes a public key from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        GroupElement::from_hex(hex).map(|x| Self(x.into()))
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

    /// Encodes the public key as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0 .0.to_bytes()).into()
    }

    /// Decodes a public key from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        GroupElement::from_slice(bytes).map(|x| Self(x.into()))
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decodes a public key from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        let x = GroupElement::from_hex(hex)?;
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

    /// Encodes the public key as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0 .0.to_bytes()).into()
    }

    /// Decodes a public key from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        GroupElement::from_slice(bytes).map(|x| Self(x.into()))
    }

    /// Encodes the public key as a hexadecimal string.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decodes a public key from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        let x = GroupElement::from_hex(hex)?;
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
    let mut rng = rand::rng();
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
    let mut rng = rand::rng();
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
    session: &crate::core::transcryption::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PyPseudonymSessionKeyPair {
    let (public, secret_key) = make_pseudonym_session_keys(
        &PseudonymGlobalSecretKey(global.0 .0),
        &session.0,
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
    session: &crate::core::transcryption::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PyAttributeSessionKeyPair {
    let (public, secret_key) = make_attribute_session_keys(
        &AttributeGlobalSecretKey(global.0 .0),
        &session.0,
        &secret.0,
    );
    PyAttributeSessionKeyPair {
        public: PyAttributeSessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(secret_key.0)),
    }
}

/// Generate new global key pairs for both pseudonyms and attributes.
#[pyfunction]
#[pyo3(name = "make_global_keys")]
pub fn py_make_global_keys() -> (PyGlobalPublicKeys, PyGlobalSecretKeys) {
    let mut rng = rand::rng();
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

/// Pseudonym session keys containing both public and secret keys.
#[pyclass(name = "PseudonymSessionKeys")]
#[derive(Clone, Copy)]
pub struct PyPseudonymSessionKeys {
    #[pyo3(get)]
    pub public: PyPseudonymSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyPseudonymSessionSecretKey,
}

#[pymethods]
impl PyPseudonymSessionKeys {
    #[new]
    fn new(public: PyPseudonymSessionPublicKey, secret: PyPseudonymSessionSecretKey) -> Self {
        PyPseudonymSessionKeys { public, secret }
    }

    fn __repr__(&self) -> String {
        format!(
            "PseudonymSessionKeys(public={}, secret=...)",
            self.public.as_hex()
        )
    }
}

/// Attribute session keys containing both public and secret keys.
#[pyclass(name = "AttributeSessionKeys")]
#[derive(Clone, Copy)]
pub struct PyAttributeSessionKeys {
    #[pyo3(get)]
    pub public: PyAttributeSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyAttributeSessionSecretKey,
}

#[pymethods]
impl PyAttributeSessionKeys {
    #[new]
    fn new(public: PyAttributeSessionPublicKey, secret: PyAttributeSessionSecretKey) -> Self {
        PyAttributeSessionKeys { public, secret }
    }

    fn __repr__(&self) -> String {
        format!(
            "AttributeSessionKeys(public={}, secret=...)",
            self.public.as_hex()
        )
    }
}

/// Session keys for encrypting and decrypting data.
/// Contains both pseudonym and attribute session keys (public and secret).
#[pyclass(name = "SessionKeys")]
#[derive(Clone)]
pub struct PySessionKeys {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymSessionKeys,
    #[pyo3(get)]
    pub attribute: PyAttributeSessionKeys,
}

#[pymethods]
impl PySessionKeys {
    /// Create new session keys.
    ///
    /// Args:
    ///     pseudonym: Pseudonym session keys
    ///     attribute: Attribute session keys
    ///
    /// Returns:
    ///     SessionKeys containing both pseudonym and attribute keys
    #[new]
    fn new(pseudonym: PyPseudonymSessionKeys, attribute: PyAttributeSessionKeys) -> Self {
        Self {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SessionKeys(pseudonym={}, attribute={})",
            self.pseudonym.__repr__(),
            self.attribute.__repr__()
        )
    }
}

impl From<PySessionKeys> for SessionKeys {
    fn from(py_keys: PySessionKeys) -> Self {
        SessionKeys {
            pseudonym: PseudonymSessionKeys {
                public: py_keys.pseudonym.public.0 .0.into(),
                secret: py_keys.pseudonym.secret.0 .0.into(),
            },
            attribute: AttributeSessionKeys {
                public: py_keys.attribute.public.0 .0.into(),
                secret: py_keys.attribute.secret.0 .0.into(),
            },
        }
    }
}

/// Generate session keys for both pseudonyms and attributes from a [`PyGlobalSecretKeys`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_session_keys")]
pub fn py_make_session_keys(
    global: &PyGlobalSecretKeys,
    session: &crate::core::transcryption::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PySessionKeys {
    let keys = make_session_keys(
        &GlobalSecretKeys {
            pseudonym: PseudonymGlobalSecretKey(global.pseudonym.0 .0),
            attribute: AttributeGlobalSecretKey(global.attribute.0 .0),
        },
        &session.0,
        &secret.0,
    );
    PySessionKeys {
        pseudonym: PyPseudonymSessionKeys {
            public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(
                keys.pseudonym.public.0,
            )),
            secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(
                keys.pseudonym.secret.0,
            )),
        },
        attribute: PyAttributeSessionKeys {
            public: PyAttributeSessionPublicKey::from(PyGroupElement::from(
                keys.attribute.public.0,
            )),
            secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(
                keys.attribute.secret.0,
            )),
        },
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add_class::<PyPseudonymSessionKeys>()?;
    m.add_class::<PyAttributeSessionKeys>()?;
    m.add_class::<PySessionKeys>()?;
    m.add_class::<PyPseudonymizationSecret>()?;
    m.add_class::<PyEncryptionSecret>()?;
    m.add_class::<PyPseudonymGlobalKeyPair>()?;
    m.add_class::<PyAttributeGlobalKeyPair>()?;
    m.add_class::<PyPseudonymSessionKeyPair>()?;
    m.add_class::<PyAttributeSessionKeyPair>()?;
    m.add_function(wrap_pyfunction!(py_make_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_keys, m)?)?;
    Ok(())
}
