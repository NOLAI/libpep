use crate::elgamal::arithmetic::group_elements::PyGroupElement;
use crate::elgamal::arithmetic::scalars::PyScalarNonZero;
use crate::macros::{py_global_pubkey_impl, py_session_pubkey_impl};
use derive_more::{Deref, From, Into};
use libpep::elgamal::arithmetic::group_elements::GroupElement;
use libpep::keys::types::*;
use libpep::keys::PublicKey;
use libpep::keys::SecretKey;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A pseudonym session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymSessionSecretKey", from_py_object)]
pub struct PyPseudonymSessionSecretKey(pub PyScalarNonZero);

/// An attribute session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeSessionSecretKey", from_py_object)]
pub struct PyAttributeSessionSecretKey(pub PyScalarNonZero);

/// A pseudonym global secret key from which pseudonym session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[pyclass(name = "PseudonymGlobalSecretKey", from_py_object)]
pub struct PyPseudonymGlobalSecretKey(pub PyScalarNonZero);

/// An attribute global secret key from which attribute session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[pyclass(name = "AttributeGlobalSecretKey", from_py_object)]
pub struct PyAttributeGlobalSecretKey(pub PyScalarNonZero);

/// A pseudonym session public key used to encrypt pseudonyms against.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymSessionPublicKey", from_py_object)]
pub struct PyPseudonymSessionPublicKey(pub PyGroupElement);

py_session_pubkey_impl!(PyPseudonymSessionPublicKey);

/// An attribute session public key used to encrypt attributes against.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeSessionPublicKey", from_py_object)]
pub struct PyAttributeSessionPublicKey(pub PyGroupElement);

py_session_pubkey_impl!(PyAttributeSessionPublicKey);

/// A pseudonym global public key from which pseudonym session keys are derived.
/// Can also be used to encrypt pseudonyms against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, PartialEq, Eq, From)]
#[pyclass(name = "PseudonymGlobalPublicKey", from_py_object)]
pub struct PyPseudonymGlobalPublicKey(pub PyGroupElement);

py_global_pubkey_impl!(PyPseudonymGlobalPublicKey as "PseudonymGlobalPublicKey");

/// An attribute global public key from which attribute session keys are derived.
/// Can also be used to encrypt attributes against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, PartialEq, Eq, From)]
#[pyclass(name = "AttributeGlobalPublicKey", from_py_object)]
pub struct PyAttributeGlobalPublicKey(pub PyGroupElement);

py_global_pubkey_impl!(PyAttributeGlobalPublicKey as "AttributeGlobalPublicKey");

/// A pair of global public keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[pyclass(name = "GlobalPublicKeys", from_py_object)]
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

impl From<PyGlobalPublicKeys> for GlobalPublicKeys {
    fn from(py_keys: PyGlobalPublicKeys) -> Self {
        GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey::from_point(py_keys.pseudonym.0 .0),
            attribute: AttributeGlobalPublicKey::from_point(py_keys.attribute.0 .0),
        }
    }
}

/// A pair of global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Debug)]
#[pyclass(name = "GlobalSecretKeys", from_py_object)]
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

impl From<PyGlobalSecretKeys> for GlobalSecretKeys {
    fn from(py_keys: PyGlobalSecretKeys) -> Self {
        GlobalSecretKeys {
            pseudonym: PseudonymGlobalSecretKey::from_scalar(py_keys.pseudonym.0 .0),
            attribute: AttributeGlobalSecretKey::from_scalar(py_keys.attribute.0 .0),
        }
    }
}

// Pseudonym global key pair
#[pyclass(name = "PseudonymGlobalKeyPair", from_py_object)]
#[derive(Copy, Clone, Debug)]
pub struct PyPseudonymGlobalKeyPair {
    #[pyo3(get)]
    pub public: PyPseudonymGlobalPublicKey,
    #[pyo3(get)]
    pub secret: PyPseudonymGlobalSecretKey,
}

// Attribute global key pair
#[pyclass(name = "AttributeGlobalKeyPair", from_py_object)]
#[derive(Copy, Clone, Debug)]
pub struct PyAttributeGlobalKeyPair {
    #[pyo3(get)]
    pub public: PyAttributeGlobalPublicKey,
    #[pyo3(get)]
    pub secret: PyAttributeGlobalSecretKey,
}

// Pseudonym session key pair
#[pyclass(name = "PseudonymSessionKeyPair", from_py_object)]
#[derive(Copy, Clone, Debug)]
pub struct PyPseudonymSessionKeyPair {
    #[pyo3(get)]
    pub public: PyPseudonymSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyPseudonymSessionSecretKey,
}

// Attribute session key pair
#[pyclass(name = "AttributeSessionKeyPair", from_py_object)]
#[derive(Copy, Clone, Debug)]
pub struct PyAttributeSessionKeyPair {
    #[pyo3(get)]
    pub public: PyAttributeSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyAttributeSessionSecretKey,
}

/// Pseudonym session keys containing both public and secret keys.
#[pyclass(name = "PseudonymSessionKeys", from_py_object)]
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
#[pyclass(name = "AttributeSessionKeys", from_py_object)]
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
#[pyclass(name = "SessionKeys", from_py_object)]
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
                public: PseudonymSessionPublicKey::from_point(py_keys.pseudonym.public.0 .0),
                secret: PseudonymSessionSecretKey::from_scalar(py_keys.pseudonym.secret.0 .0),
            },
            attribute: AttributeSessionKeys {
                public: AttributeSessionPublicKey::from_point(py_keys.attribute.public.0 .0),
                secret: AttributeSessionSecretKey::from_scalar(py_keys.attribute.secret.0 .0),
            },
        }
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
    m.add_class::<PyPseudonymGlobalKeyPair>()?;
    m.add_class::<PyAttributeGlobalKeyPair>()?;
    m.add_class::<PyPseudonymSessionKeyPair>()?;
    m.add_class::<PyAttributeSessionKeyPair>()?;
    Ok(())
}
