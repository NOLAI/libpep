use super::blinding::{
    PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalKeys, PyBlindedPseudonymGlobalSecretKey,
    PyBlindingFactor,
};
use crate::arithmetic::py::{PyGroupElement, PyScalarNonZero};
use crate::arithmetic::scalars::ScalarTraits;
use crate::client::distributed::{
    make_attribute_session_key, make_pseudonym_session_key, make_session_keys_distributed,
    update_attribute_session_key, update_pseudonym_session_key, update_session_keys,
};
use crate::keys::distribution::*;
use crate::keys::py::types::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey,
};
use crate::keys::*;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A pseudonym session key share.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymSessionKeyShare")]
pub struct PyPseudonymSessionKeyShare(pub(crate) PseudonymSessionKeyShare);

#[pymethods]
impl PyPseudonymSessionKeyShare {
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyPseudonymSessionKeyShare(PseudonymSessionKeyShare(x.0))
    }

    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<PyPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::from_slice(bytes).map(PyPseudonymSessionKeyShare)
    }

    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::from_hex(hex).map(PyPseudonymSessionKeyShare)
    }

    fn __repr__(&self) -> String {
        format!("PseudonymSessionKeyShare({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyPseudonymSessionKeyShare) -> bool {
        self.0 == other.0
    }
}

/// An attribute session key share.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeSessionKeyShare")]
pub struct PyAttributeSessionKeyShare(pub(crate) AttributeSessionKeyShare);

#[pymethods]
impl PyAttributeSessionKeyShare {
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyAttributeSessionKeyShare(AttributeSessionKeyShare(x.0))
    }

    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<PyAttributeSessionKeyShare> {
        AttributeSessionKeyShare::from_slice(bytes).map(PyAttributeSessionKeyShare)
    }

    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyAttributeSessionKeyShare> {
        AttributeSessionKeyShare::from_hex(hex).map(PyAttributeSessionKeyShare)
    }

    fn __repr__(&self) -> String {
        format!("AttributeSessionKeyShare({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyAttributeSessionKeyShare) -> bool {
        self.0 == other.0
    }
}

/// A pair of session key shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "SessionKeyShares")]
pub struct PySessionKeyShares {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymSessionKeyShare,
    #[pyo3(get)]
    pub attribute: PyAttributeSessionKeyShare,
}

#[pymethods]
impl PySessionKeyShares {
    #[new]
    fn new(pseudonym: PyPseudonymSessionKeyShare, attribute: PyAttributeSessionKeyShare) -> Self {
        PySessionKeyShares {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SessionKeyShares(pseudonym={}, attribute={})",
            self.pseudonym.as_hex(),
            self.attribute.as_hex()
        )
    }

    fn __eq__(&self, other: &PySessionKeyShares) -> bool {
        self.pseudonym == other.pseudonym && self.attribute == other.attribute
    }
}

/// Session public keys pair.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "SessionPublicKeys")]
pub struct PySessionPublicKeys {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymSessionPublicKey,
    #[pyo3(get)]
    pub attribute: PyAttributeSessionPublicKey,
}

#[pymethods]
impl PySessionPublicKeys {
    #[new]
    fn new(pseudonym: PyPseudonymSessionPublicKey, attribute: PyAttributeSessionPublicKey) -> Self {
        PySessionPublicKeys {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SessionPublicKeys(pseudonym={}, attribute={})",
            self.pseudonym.0.to_hex(),
            self.attribute.0.to_hex()
        )
    }

    fn __eq__(&self, other: &PySessionPublicKeys) -> bool {
        self.pseudonym == other.pseudonym && self.attribute == other.attribute
    }
}

/// Session secret keys pair.
#[derive(Copy, Clone, Debug, From, Into)]
#[pyclass(name = "SessionSecretKeys")]
pub struct PySessionSecretKeys {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymSessionSecretKey,
    #[pyo3(get)]
    pub attribute: PyAttributeSessionSecretKey,
}

#[pymethods]
impl PySessionSecretKeys {
    #[new]
    fn new(pseudonym: PyPseudonymSessionSecretKey, attribute: PyAttributeSessionSecretKey) -> Self {
        PySessionSecretKeys {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        "SessionSecretKeys(pseudonym=..., attribute=...)".to_string()
    }
}

/// Session keys (public and secret) for both pseudonyms and attributes.
/// This is an alternative structure that splits by public/secret instead of pseudonym/attribute.
/// Note: Not registered as "SessionKeys" to avoid conflict with the main SessionKeys type in types.rs.
#[derive(Clone, From, Into)]
#[pyclass(name = "SessionKeysPublicSecret")]
pub struct PySessionKeys {
    #[pyo3(get)]
    pub public: PySessionPublicKeys,
    #[pyo3(get)]
    pub secret: PySessionSecretKeys,
}

#[pymethods]
impl PySessionKeys {
    #[new]
    fn new(public: PySessionPublicKeys, secret: PySessionSecretKeys) -> Self {
        PySessionKeys { public, secret }
    }

    fn __repr__(&self) -> String {
        format!(
            "SessionKeysPublicSecret(public={}, secret=...)",
            self.public.__repr__()
        )
    }
}

// Key pair types
#[pyclass(name = "PseudonymSessionKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PyPseudonymSessionKeyPair {
    #[pyo3(get)]
    pub public: PyPseudonymSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyPseudonymSessionSecretKey,
}

#[pyclass(name = "AttributeSessionKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PyAttributeSessionKeyPair {
    #[pyo3(get)]
    pub public: PyAttributeSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyAttributeSessionSecretKey,
}

/// Reconstruct pseudonym session keys from blinded global secret key and shares.
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_key")]
pub fn py_make_pseudonym_session_key(
    blinded_global_secret_key: PyBlindedPseudonymGlobalSecretKey,
    session_key_shares: Vec<PyPseudonymSessionKeyShare>,
) -> PyPseudonymSessionKeyPair {
    let shares: Vec<PseudonymSessionKeyShare> = session_key_shares.iter().map(|s| s.0).collect();
    let (public, secret) = make_pseudonym_session_key(blinded_global_secret_key.0, &shares);
    PyPseudonymSessionKeyPair {
        public: PyPseudonymSessionPublicKey(PyGroupElement(public.0)),
        secret: PyPseudonymSessionSecretKey(PyScalarNonZero(secret.0)),
    }
}

/// Reconstruct attribute session keys from blinded global secret key and shares.
#[pyfunction]
#[pyo3(name = "make_attribute_session_key")]
pub fn py_make_attribute_session_key(
    blinded_global_secret_key: PyBlindedAttributeGlobalSecretKey,
    session_key_shares: Vec<PyAttributeSessionKeyShare>,
) -> PyAttributeSessionKeyPair {
    let shares: Vec<AttributeSessionKeyShare> = session_key_shares.iter().map(|s| s.0).collect();
    let (public, secret) = make_attribute_session_key(blinded_global_secret_key.0, &shares);
    PyAttributeSessionKeyPair {
        public: PyAttributeSessionPublicKey(PyGroupElement(public.0)),
        secret: PyAttributeSessionSecretKey(PyScalarNonZero(secret.0)),
    }
}

/// Reconstruct session keys from blinded global keys and shares.
#[pyfunction]
#[pyo3(name = "make_session_keys_distributed")]
pub fn py_make_session_keys_distributed(
    blinded_global_keys: &PyBlindedGlobalKeys,
    session_key_shares: Vec<PySessionKeyShares>,
) -> PySessionKeys {
    let shares: Vec<SessionKeyShares> = session_key_shares
        .iter()
        .map(|s| SessionKeyShares {
            pseudonym: s.pseudonym.0,
            attribute: s.attribute.0,
        })
        .collect();
    let blinded_keys = BlindedGlobalKeys {
        pseudonym: blinded_global_keys.pseudonym.0,
        attribute: blinded_global_keys.attribute.0,
    };
    let keys = make_session_keys_distributed(blinded_keys, &shares);
    PySessionKeys {
        public: PySessionPublicKeys {
            pseudonym: PyPseudonymSessionPublicKey(PyGroupElement(keys.pseudonym.public.0)),
            attribute: PyAttributeSessionPublicKey(PyGroupElement(keys.attribute.public.0)),
        },
        secret: PySessionSecretKeys {
            pseudonym: PyPseudonymSessionSecretKey(PyScalarNonZero(keys.pseudonym.secret.0)),
            attribute: PyAttributeSessionSecretKey(PyScalarNonZero(keys.attribute.secret.0)),
        },
    }
}

/// Update pseudonym session keys with new share.
#[pyfunction]
#[pyo3(name = "update_pseudonym_session_key")]
pub fn py_update_pseudonym_session_key(
    session_secret_key: PyPseudonymSessionSecretKey,
    old_session_key_share: PyPseudonymSessionKeyShare,
    new_session_key_share: PyPseudonymSessionKeyShare,
) -> PyPseudonymSessionKeyPair {
    let (public, secret) = update_pseudonym_session_key(
        session_secret_key.0 .0.into(),
        old_session_key_share.0,
        new_session_key_share.0,
    );
    PyPseudonymSessionKeyPair {
        public: PyPseudonymSessionPublicKey(PyGroupElement(public.0)),
        secret: PyPseudonymSessionSecretKey(PyScalarNonZero(secret.0)),
    }
}

/// Update attribute session keys with new share.
#[pyfunction]
#[pyo3(name = "update_attribute_session_key")]
pub fn py_update_attribute_session_key(
    session_secret_key: PyAttributeSessionSecretKey,
    old_session_key_share: PyAttributeSessionKeyShare,
    new_session_key_share: PyAttributeSessionKeyShare,
) -> PyAttributeSessionKeyPair {
    let (public, secret) = update_attribute_session_key(
        session_secret_key.0 .0.into(),
        old_session_key_share.0,
        new_session_key_share.0,
    );
    PyAttributeSessionKeyPair {
        public: PyAttributeSessionPublicKey(PyGroupElement(public.0)),
        secret: PyAttributeSessionSecretKey(PyScalarNonZero(secret.0)),
    }
}

/// Update session keys with new shares.
#[pyfunction]
#[pyo3(name = "update_session_keys")]
pub fn py_update_session_keys(
    current_keys: &PySessionKeys,
    old_shares: &PySessionKeyShares,
    new_shares: &PySessionKeyShares,
) -> PySessionKeys {
    let current = SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: current_keys.public.pseudonym.0 .0.into(),
            secret: current_keys.secret.pseudonym.0 .0.into(),
        },
        attribute: AttributeSessionKeys {
            public: current_keys.public.attribute.0 .0.into(),
            secret: current_keys.secret.attribute.0 .0.into(),
        },
    };
    let old = SessionKeyShares {
        pseudonym: old_shares.pseudonym.0,
        attribute: old_shares.attribute.0,
    };
    let new = SessionKeyShares {
        pseudonym: new_shares.pseudonym.0,
        attribute: new_shares.attribute.0,
    };
    let updated = update_session_keys(current, old, new);
    PySessionKeys {
        public: PySessionPublicKeys {
            pseudonym: PyPseudonymSessionPublicKey(PyGroupElement(updated.pseudonym.public.0)),
            attribute: PyAttributeSessionPublicKey(PyGroupElement(updated.attribute.public.0)),
        },
        secret: PySessionSecretKeys {
            pseudonym: PyPseudonymSessionSecretKey(PyScalarNonZero(updated.pseudonym.secret.0)),
            attribute: PyAttributeSessionSecretKey(PyScalarNonZero(updated.attribute.secret.0)),
        },
    }
}

// Conversion from PySessionKeys to SessionKeys
impl From<PySessionKeys> for SessionKeys {
    fn from(py_keys: PySessionKeys) -> Self {
        SessionKeys {
            pseudonym: PseudonymSessionKeys {
                public: PseudonymSessionPublicKey(py_keys.public.pseudonym.0 .0),
                secret: PseudonymSessionSecretKey(py_keys.secret.pseudonym.0 .0),
            },
            attribute: AttributeSessionKeys {
                public: AttributeSessionPublicKey(py_keys.public.attribute.0 .0),
                secret: AttributeSessionSecretKey(py_keys.secret.attribute.0 .0),
            },
        }
    }
}

/// Create a pseudonym session key share.
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_key_share")]
pub fn py_make_pseudonym_session_key_share(
    rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PyPseudonymSessionKeyShare {
    use crate::factors::types::PseudonymRekeyFactor;
    use crate::keys::distribution::make_pseudonym_session_key_share;
    PyPseudonymSessionKeyShare(make_pseudonym_session_key_share(
        &PseudonymRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Create an attribute session key share.
#[pyfunction]
#[pyo3(name = "make_attribute_session_key_share")]
pub fn py_make_attribute_session_key_share(
    rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PyAttributeSessionKeyShare {
    use crate::factors::types::AttributeRekeyFactor;
    use crate::keys::distribution::make_attribute_session_key_share;
    PyAttributeSessionKeyShare(make_attribute_session_key_share(
        &AttributeRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Create session key shares.
#[pyfunction]
#[pyo3(name = "make_session_key_shares")]
pub fn py_make_session_key_shares(
    pseudonym_rekey_factor: &PyScalarNonZero,
    attribute_rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PySessionKeyShares {
    use crate::factors::types::{AttributeRekeyFactor, PseudonymRekeyFactor};
    use crate::keys::distribution::make_session_key_shares;
    let shares = make_session_key_shares(
        &PseudonymRekeyFactor::from(pseudonym_rekey_factor.0),
        &AttributeRekeyFactor::from(attribute_rekey_factor.0),
        &blinding_factor.0,
    );
    PySessionKeyShares {
        pseudonym: PyPseudonymSessionKeyShare(shares.pseudonym),
        attribute: PyAttributeSessionKeyShare(shares.attribute),
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonymSessionKeyShare>()?;
    m.add_class::<PyAttributeSessionKeyShare>()?;
    m.add_class::<PySessionKeyShares>()?;
    m.add_class::<PySessionPublicKeys>()?;
    m.add_class::<PySessionSecretKeys>()?;
    m.add_class::<PySessionKeys>()?;
    m.add_class::<PyPseudonymSessionKeyPair>()?;
    m.add_class::<PyAttributeSessionKeyPair>()?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_keys_distributed, m)?)?;
    m.add_function(wrap_pyfunction!(py_update_pseudonym_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_update_attribute_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_update_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_key_share, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_key_share, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_key_shares, m)?)?;
    Ok(())
}
