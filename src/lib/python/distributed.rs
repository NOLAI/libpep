use crate::distributed::key_blinding::*;
use crate::distributed::systems::*;
use crate::high_level::contexts::*;
use crate::high_level::data_types::{EncryptedAttribute, EncryptedPseudonym};
use crate::high_level::keys::*;
use crate::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::python::arithmetic::*;
use crate::python::high_level::*;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug, From, Into, Deref)]
#[pyclass(name = "BlindingFactor")]
pub struct PyBlindingFactor(BlindingFactor);

#[pymethods]
impl PyBlindingFactor {
    /// Create a new [`PyBlindingFactor`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyBlindingFactor(BlindingFactor(x.0))
    }

    /// Generate a random [`PyBlindingFactor`].
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> Self {
        let mut rng = rand::thread_rng();
        let x = BlindingFactor::random(&mut rng);
        PyBlindingFactor(x)
    }

    /// Encode the [`PyBlindingFactor`] as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decode a [`PyBlindingFactor`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyBlindingFactor> {
        BlindingFactor::decode_from_slice(bytes).map(PyBlindingFactor)
    }

    /// Encode the [`PyBlindingFactor`] as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a [`PyBlindingFactor`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyBlindingFactor> {
        BlindingFactor::decode_from_hex(hex).map(PyBlindingFactor)
    }

    fn __repr__(&self) -> String {
        format!("BlindingFactor({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyBlindingFactor) -> bool {
        self.0 .0 == other.0 .0
    }
}

/// A blinded pseudonym global secret key, which is the pseudonym global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "BlindedPseudonymGlobalSecretKey")]
pub struct PyBlindedPseudonymGlobalSecretKey(BlindedPseudonymGlobalSecretKey);

#[pymethods]
impl PyBlindedPseudonymGlobalSecretKey {
    /// Create a new [`PyBlindedPseudonymGlobalSecretKey`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyBlindedPseudonymGlobalSecretKey(BlindedPseudonymGlobalSecretKey(x.0))
    }

    /// Encode the [`PyBlindedPseudonymGlobalSecretKey`] as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decode a [`PyBlindedPseudonymGlobalSecretKey`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::decode_from_slice(bytes)
            .map(PyBlindedPseudonymGlobalSecretKey)
    }

    /// Encode the [`PyBlindedPseudonymGlobalSecretKey`] as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a [`PyBlindedPseudonymGlobalSecretKey`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::decode_from_hex(hex).map(PyBlindedPseudonymGlobalSecretKey)
    }

    fn __repr__(&self) -> String {
        format!("BlindedPseudonymGlobalSecretKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyBlindedPseudonymGlobalSecretKey) -> bool {
        self.0 == other.0
    }
}

/// A blinded attribute global secret key, which is the attribute global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "BlindedAttributeGlobalSecretKey")]
pub struct PyBlindedAttributeGlobalSecretKey(BlindedAttributeGlobalSecretKey);

#[pymethods]
impl PyBlindedAttributeGlobalSecretKey {
    /// Create a new [`PyBlindedAttributeGlobalSecretKey`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyBlindedAttributeGlobalSecretKey(BlindedAttributeGlobalSecretKey(x.0))
    }

    /// Encode the [`PyBlindedAttributeGlobalSecretKey`] as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decode a [`PyBlindedAttributeGlobalSecretKey`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::decode_from_slice(bytes)
            .map(PyBlindedAttributeGlobalSecretKey)
    }

    /// Encode the [`PyBlindedAttributeGlobalSecretKey`] as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a [`PyBlindedAttributeGlobalSecretKey`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::decode_from_hex(hex).map(PyBlindedAttributeGlobalSecretKey)
    }

    fn __repr__(&self) -> String {
        format!("BlindedAttributeGlobalSecretKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyBlindedAttributeGlobalSecretKey) -> bool {
        self.0 == other.0
    }
}

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`PyBlindedPseudonymGlobalSecretKey`], a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymSessionKeyShare")]
pub struct PyPseudonymSessionKeyShare(PseudonymSessionKeyShare);

#[pymethods]
impl PyPseudonymSessionKeyShare {
    /// Create a new [`PyPseudonymSessionKeyShare`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyPseudonymSessionKeyShare(PseudonymSessionKeyShare(x.0))
    }

    /// Encode the [`PyPseudonymSessionKeyShare`] as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decode a [`PyPseudonymSessionKeyShare`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::decode_from_slice(bytes).map(PyPseudonymSessionKeyShare)
    }

    /// Encode the [`PyPseudonymSessionKeyShare`] as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a [`PyPseudonymSessionKeyShare`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::decode_from_hex(hex).map(PyPseudonymSessionKeyShare)
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

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`PyBlindedAttributeGlobalSecretKey`], an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeSessionKeyShare")]
pub struct PyAttributeSessionKeyShare(AttributeSessionKeyShare);

#[pymethods]
impl PyAttributeSessionKeyShare {
    /// Create a new [`PyAttributeSessionKeyShare`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyAttributeSessionKeyShare(AttributeSessionKeyShare(x.0))
    }

    /// Encode the [`PyAttributeSessionKeyShare`] as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.encode()).into()
    }

    /// Decode a [`PyAttributeSessionKeyShare`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyAttributeSessionKeyShare> {
        AttributeSessionKeyShare::decode_from_slice(bytes).map(PyAttributeSessionKeyShare)
    }

    /// Encode the [`PyAttributeSessionKeyShare`] as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a [`PyAttributeSessionKeyShare`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyAttributeSessionKeyShare> {
        AttributeSessionKeyShare::decode_from_hex(hex).map(PyAttributeSessionKeyShare)
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

/// A pair of session key shares containing both pseudonym and attribute shares.
/// This simplifies the API by combining both shares that are always used together.
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
    /// Create a new [`PySessionKeyShares`] from pseudonym and attribute shares.
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

/// A pair of blinded global secret keys containing both pseudonym and attribute keys.
/// This simplifies the API by combining both keys that are always used together.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "BlindedGlobalKeys")]
pub struct PyBlindedGlobalKeys {
    #[pyo3(get)]
    pub pseudonym: PyBlindedPseudonymGlobalSecretKey,
    #[pyo3(get)]
    pub attribute: PyBlindedAttributeGlobalSecretKey,
}

#[pymethods]
impl PyBlindedGlobalKeys {
    /// Create a new [`PyBlindedGlobalKeys`] from pseudonym and attribute blinded keys.
    #[new]
    fn new(
        pseudonym: PyBlindedPseudonymGlobalSecretKey,
        attribute: PyBlindedAttributeGlobalSecretKey,
    ) -> Self {
        PyBlindedGlobalKeys {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "BlindedGlobalKeys(pseudonym={}, attribute={})",
            self.pseudonym.as_hex(),
            self.attribute.as_hex()
        )
    }

    fn __eq__(&self, other: &PyBlindedGlobalKeys) -> bool {
        self.pseudonym == other.pseudonym && self.attribute == other.attribute
    }
}

/// A pair of session public keys containing both pseudonym and attribute public keys.
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
    /// Create a new [`PySessionPublicKeys`] from pseudonym and attribute public keys.
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
            self.pseudonym.0.encode_as_hex(),
            self.attribute.0.encode_as_hex()
        )
    }

    fn __eq__(&self, other: &PySessionPublicKeys) -> bool {
        self.pseudonym == other.pseudonym && self.attribute == other.attribute
    }
}

/// A pair of session secret keys containing both pseudonym and attribute secret keys.
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
    /// Create a new [`PySessionSecretKeys`] from pseudonym and attribute secret keys.
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

/// A pair of session key pairs (public and secret) for both pseudonyms and attributes.
#[derive(Clone, From, Into)]
#[pyclass(name = "SessionKeys")]
pub struct PySessionKeys {
    #[pyo3(get)]
    pub public: PySessionPublicKeys,
    #[pyo3(get)]
    pub secret: PySessionSecretKeys,
}

#[pymethods]
impl PySessionKeys {
    /// Create a new [`PySessionKeys`] from public and secret keys.
    #[new]
    fn new(public: PySessionPublicKeys, secret: PySessionSecretKeys) -> Self {
        PySessionKeys { public, secret }
    }

    fn __repr__(&self) -> String {
        format!("SessionKeys(public={}, secret=...)", self.public.__repr__())
    }
}

/// Create a blinded pseudonym global secret key from a pseudonym global secret key and blinding factors.
#[pyfunction]
#[pyo3(name = "make_blinded_pseudonym_global_secret_key")]
pub fn py_make_blinded_pseudonym_global_secret_key(
    global_secret_key: &PyPseudonymGlobalSecretKey,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedPseudonymGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_pseudonym_global_secret_key(
        &PseudonymGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedPseudonymGlobalSecretKey(result))
}

/// Create a blinded attribute global secret key from an attribute global secret key and blinding factors.
#[pyfunction]
#[pyo3(name = "make_blinded_attribute_global_secret_key")]
pub fn py_make_blinded_attribute_global_secret_key(
    global_secret_key: &PyAttributeGlobalSecretKey,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedAttributeGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_attribute_global_secret_key(
        &AttributeGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedAttributeGlobalSecretKey(result))
}

/// Create [`PyBlindedGlobalKeys`] (both pseudonym and attribute) from global secret keys and blinding factors.
/// Returns an error if the product of all blinding factors accidentally turns out to be 1 for either key type.
#[pyfunction]
#[pyo3(name = "make_blinded_global_keys")]
pub fn py_make_blinded_global_keys(
    global_secret_keys: &PyGlobalSecretKeys,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedGlobalKeys> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_global_keys(
        &PseudonymGlobalSecretKey::from(global_secret_keys.pseudonym.0 .0),
        &AttributeGlobalSecretKey::from(global_secret_keys.attribute.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedGlobalKeys {
        pseudonym: PyBlindedPseudonymGlobalSecretKey(result.pseudonym),
        attribute: PyBlindedAttributeGlobalSecretKey(result.attribute),
    })
}

/// Create a pseudonym session key share from a rekey factor and blinding factor.
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_key_share")]
pub fn py_make_pseudonym_session_key_share(
    rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PyPseudonymSessionKeyShare {
    PyPseudonymSessionKeyShare(make_pseudonym_session_key_share(
        &rekey_factor.0,
        &blinding_factor.0,
    ))
}

/// Create an attribute session key share from a rekey factor and blinding factor.
#[pyfunction]
#[pyo3(name = "make_attribute_session_key_share")]
pub fn py_make_attribute_session_key_share(
    rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PyAttributeSessionKeyShare {
    PyAttributeSessionKeyShare(make_attribute_session_key_share(
        &rekey_factor.0,
        &blinding_factor.0,
    ))
}

/// Create session key shares (both pseudonym and attribute) from rekey factors and blinding factor.
#[pyfunction]
#[pyo3(name = "make_session_key_shares")]
pub fn py_make_session_key_shares(
    pseudonym_rekey_factor: &PyScalarNonZero,
    attribute_rekey_factor: &PyScalarNonZero,
    blinding_factor: &PyBlindingFactor,
) -> PySessionKeyShares {
    let shares = make_session_key_shares(
        &pseudonym_rekey_factor.0,
        &attribute_rekey_factor.0,
        &blinding_factor.0,
    );
    PySessionKeyShares {
        pseudonym: PyPseudonymSessionKeyShare(shares.pseudonym),
        attribute: PyAttributeSessionKeyShare(shares.attribute),
    }
}

/// Reconstruct pseudonym session keys from blinded global secret key and session key shares.
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

/// Reconstruct attribute session keys from blinded global secret key and session key shares.
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

/// Reconstruct session keys (both pseudonym and attribute) from blinded global keys and session key shares.
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

/// Update pseudonym session keys with new session key share.
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

/// Update attribute session keys with new session key share.
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

/// Update session keys (both pseudonym and attribute) with new session key shares.
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

/// Generate session keys (both pseudonym and attribute) from global secret keys.
#[pyfunction]
#[pyo3(name = "make_session_keys")]
pub fn py_make_session_keys(
    global: &PyGlobalSecretKeys,
    session: &str,
    secret: &PyEncryptionSecret,
) -> PySessionKeys {
    let global_keys = GlobalSecretKeys {
        pseudonym: PseudonymGlobalSecretKey(global.pseudonym.0 .0),
        attribute: AttributeGlobalSecretKey(global.attribute.0 .0),
    };
    let keys = make_session_keys(&global_keys, &EncryptionContext::from(session), &secret.0);

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

/// Setup a distributed system with pseudonym global keys, blinded global secret key and blinding factors.
#[pyfunction]
#[pyo3(name = "make_distributed_pseudonym_global_keys")]
pub fn py_make_distributed_pseudonym_global_keys(
    n: usize,
) -> (
    PyPseudonymGlobalPublicKey,
    PyBlindedPseudonymGlobalSecretKey,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::thread_rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_pseudonym_global_keys(n, &mut rng);

    (
        PyPseudonymGlobalPublicKey(PyGroupElement(public_key.0)),
        PyBlindedPseudonymGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

/// Setup a distributed system with attribute global keys, blinded global secret key and blinding factors.
#[pyfunction]
#[pyo3(name = "make_distributed_attribute_global_keys")]
pub fn py_make_distributed_attribute_global_keys(
    n: usize,
) -> (
    PyAttributeGlobalPublicKey,
    PyBlindedAttributeGlobalSecretKey,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::thread_rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_attribute_global_keys(n, &mut rng);

    (
        PyAttributeGlobalPublicKey(PyGroupElement(public_key.0)),
        PyBlindedAttributeGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

/// Setup a distributed system with both pseudonym and attribute global keys, blinded global secret keys,
/// and a list of blinding factors.
/// The blinding factors should securely be transferred to the transcryptors, the global public keys
/// and blinded global secret keys can be publicly shared with anyone and are required by clients.
#[pyfunction]
#[pyo3(name = "make_distributed_global_keys")]
pub fn py_make_distributed_global_keys(
    n: usize,
) -> (
    PyGlobalPublicKeys,
    PyBlindedGlobalKeys,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::thread_rng();
    let (global_public_keys, blinded_keys, blinding_factors) =
        make_distributed_global_keys(n, &mut rng);

    (
        PyGlobalPublicKeys {
            pseudonym: PyPseudonymGlobalPublicKey(PyGroupElement(global_public_keys.pseudonym.0)),
            attribute: PyAttributeGlobalPublicKey(PyGroupElement(global_public_keys.attribute.0)),
        },
        PyBlindedGlobalKeys {
            pseudonym: PyBlindedPseudonymGlobalSecretKey(blinded_keys.pseudonym),
            attribute: PyBlindedAttributeGlobalSecretKey(blinded_keys.attribute),
        },
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

/// A PEP transcryptor system that can pseudonymize and rekey data, based on
/// a pseudonymisation secret, a rekeying secret and a blinding factor.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "PEPSystem")]
pub struct PyPEPSystem(PEPSystem);

#[pymethods]
impl PyPEPSystem {
    /// Create a new PEP system with the given secrets and blinding factor.
    #[new]
    fn new(
        pseudonymisation_secret: &str,
        rekeying_secret: &str,
        blinding_factor: &PyBlindingFactor,
    ) -> Self {
        Self(PEPSystem::new(
            PseudonymizationSecret::from(pseudonymisation_secret.as_bytes().to_vec()),
            EncryptionSecret::from(rekeying_secret.as_bytes().to_vec()),
            BlindingFactor(blinding_factor.0 .0),
        ))
    }

    /// Generate a pseudonym session key share for the given session.
    #[pyo3(name = "pseudonym_session_key_share")]
    fn py_pseudonym_session_key_share(&self, session: &str) -> PyPseudonymSessionKeyShare {
        PyPseudonymSessionKeyShare(
            self.pseudonym_session_key_share(&EncryptionContext::from(session)),
        )
    }

    /// Generate an attribute session key share for the given session.
    #[pyo3(name = "attribute_session_key_share")]
    fn py_attribute_session_key_share(&self, session: &str) -> PyAttributeSessionKeyShare {
        PyAttributeSessionKeyShare(
            self.attribute_session_key_share(&EncryptionContext::from(session)),
        )
    }

    /// Generate both pseudonym and attribute session key shares for the given session.
    /// This is a convenience method that returns both shares together.
    #[pyo3(name = "session_key_shares")]
    fn py_session_key_shares(&self, session: &str) -> PySessionKeyShares {
        let shares = self.session_key_shares(&EncryptionContext::from(session));
        PySessionKeyShares {
            pseudonym: PyPseudonymSessionKeyShare(shares.pseudonym),
            attribute: PyAttributeSessionKeyShare(shares.attribute),
        }
    }

    /// Generate attribute rekey info to rekey from a given session to another.
    #[pyo3(name = "attribute_rekey_info", signature = (session_from=None, session_to=None))]
    fn py_attribute_rekey_info(
        &self,
        session_from: Option<&str>,
        session_to: Option<&str>,
    ) -> PyAttributeRekeyInfo {
        PyAttributeRekeyInfo::from(self.attribute_rekey_info(
            session_from.map(EncryptionContext::from).as_ref(),
            session_to.map(EncryptionContext::from).as_ref(),
        ))
    }

    /// Generate a pseudonym rekey info to rekey pseudonyms from a given session to another.
    #[pyo3(name = "pseudonym_rekey_info", signature = (session_from=None, session_to=None))]
    fn py_pseudonym_rekey_info(
        &self,
        session_from: Option<&str>,
        session_to: Option<&str>,
    ) -> PyPseudonymRekeyFactor {
        PyPseudonymRekeyFactor(self.pseudonym_rekey_info(
            session_from.map(EncryptionContext::from).as_ref(),
            session_to.map(EncryptionContext::from).as_ref(),
        ))
    }

    /// Generate a pseudonymization info to pseudonymize from a given pseudonymization domain
    /// and session to another.
    #[pyo3(name = "pseudonymization_info", signature = (domain_from, domain_to, session_from=None, session_to=None))]
    fn py_pseudonymization_info(
        &self,
        domain_from: &str,
        domain_to: &str,
        session_from: Option<&str>,
        session_to: Option<&str>,
    ) -> PyPseudonymizationInfo {
        PyPseudonymizationInfo::from(self.pseudonymization_info(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            session_from.map(EncryptionContext::from).as_ref(),
            session_to.map(EncryptionContext::from).as_ref(),
        ))
    }

    /// Generate transcryption info to transcrypt from a given pseudonymization domain and session to another.
    #[pyo3(name = "transcryption_info", signature = (domain_from, domain_to, session_from=None, session_to=None))]
    fn py_transcryption_info(
        &self,
        domain_from: &str,
        domain_to: &str,
        session_from: Option<&str>,
        session_to: Option<&str>,
    ) -> PyTranscryptionInfo {
        PyTranscryptionInfo::from(self.transcryption_info(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            session_from.map(EncryptionContext::from).as_ref(),
            session_to.map(EncryptionContext::from).as_ref(),
        ))
    }

    /// Rekey an [`PyEncryptedAttribute`] from one session to another, using [`PyAttributeRekeyInfo`].
    #[pyo3(name = "rekey")]
    fn py_rekey(
        &self,
        encrypted: &PyEncryptedAttribute,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> PyEncryptedAttribute {
        PyEncryptedAttribute::from(self.rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)))
    }

    /// Pseudonymize an [`PyEncryptedPseudonym`] from one pseudonymization domain and session to
    /// another, using [`PyPseudonymizationInfo`].
    #[pyo3(name = "pseudonymize")]
    fn py_pseudonymize(
        &self,
        encrypted: &PyEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
    ) -> PyEncryptedPseudonym {
        PyEncryptedPseudonym::from(
            self.pseudonymize(&encrypted.0, &PseudonymizationInfo::from(pseudo_info)),
        )
    }

    /// Rekey a batch of [`PyEncryptedAttribute`]s from one session to another, using [`PyAttributeRekeyInfo`].
    #[pyo3(name = "rekey_batch")]
    fn py_rekey_batch(
        &self,
        encrypted: Vec<PyEncryptedAttribute>,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> Vec<PyEncryptedAttribute> {
        let mut rng = rand::thread_rng();
        let mut encrypted: Vec<EncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self.rekey_batch(
            &mut encrypted,
            &AttributeRekeyInfo::from(rekey_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(PyEncryptedAttribute::from)
            .collect()
    }

    /// Pseudonymize a batch of [`PyEncryptedPseudonym`]s from one pseudonymization domain and
    /// session to another, using [`PyPseudonymizationInfo`].
    #[pyo3(name = "pseudonymize_batch")]
    fn py_pseudonymize_batch(
        &self,
        encrypted: Vec<PyEncryptedPseudonym>,
        pseudonymization_info: &PyPseudonymizationInfo,
    ) -> Vec<PyEncryptedPseudonym> {
        let mut rng = rand::thread_rng();
        let mut encrypted: Vec<EncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self.pseudonymize_batch(
            &mut encrypted,
            &PseudonymizationInfo::from(pseudonymization_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(PyEncryptedPseudonym::from)
            .collect()
    }
}

/// A PEP client that can encrypt and decrypt data, based on separate session key pairs for pseudonyms and attributes.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "PEPClient")]
pub struct PyPEPClient(PEPClient);

#[pymethods]
impl PyPEPClient {
    /// Create a new PEP client from blinded global keys and session key shares.
    #[new]
    fn new(
        blinded_global_keys: &PyBlindedGlobalKeys,
        session_key_shares: Vec<PySessionKeyShares>,
    ) -> Self {
        let shares: Vec<SessionKeyShares> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShares {
                pseudonym: PseudonymSessionKeyShare(x.pseudonym.0 .0),
                attribute: AttributeSessionKeyShare(x.attribute.0 .0),
            })
            .collect();
        let blinded_keys = BlindedGlobalKeys {
            pseudonym: blinded_global_keys.pseudonym.0,
            attribute: blinded_global_keys.attribute.0,
        };
        Self(PEPClient::new(blinded_keys, &shares))
    }

    /// Restore a PEP client from the given session keys.
    #[staticmethod]
    #[pyo3(name = "restore")]
    fn py_restore(keys: &PySessionKeys) -> Self {
        let keys = SessionKeys {
            pseudonym: PseudonymSessionKeys {
                public: PseudonymSessionPublicKey(keys.public.pseudonym.0 .0),
                secret: PseudonymSessionSecretKey(keys.secret.pseudonym.0 .0),
            },
            attribute: AttributeSessionKeys {
                public: AttributeSessionPublicKey(keys.public.attribute.0 .0),
                secret: AttributeSessionSecretKey(keys.secret.attribute.0 .0),
            },
        };
        Self(PEPClient::restore(keys))
    }

    /// Dump the session keys.
    #[pyo3(name = "dump")]
    fn py_dump(&self) -> PySessionKeys {
        let keys = self.0.dump();
        PySessionKeys {
            public: PySessionPublicKeys {
                pseudonym: PyPseudonymSessionPublicKey::from(PyGroupElement::from(
                    keys.pseudonym.public.0,
                )),
                attribute: PyAttributeSessionPublicKey::from(PyGroupElement::from(
                    keys.attribute.public.0,
                )),
            },
            secret: PySessionSecretKeys {
                pseudonym: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(
                    keys.pseudonym.secret.0,
                )),
                attribute: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(
                    keys.attribute.secret.0,
                )),
            },
        }
    }

    /// Update a pseudonym session key share from one session to the other
    #[pyo3(name = "update_pseudonym_session_secret_key")]
    fn py_update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: PyPseudonymSessionKeyShare,
        new_key_share: PyPseudonymSessionKeyShare,
    ) {
        self.0
            .update_pseudonym_session_secret_key(old_key_share.0, new_key_share.0);
    }

    /// Update an attribute session key share from one session to the other
    #[pyo3(name = "update_attribute_session_secret_key")]
    fn py_update_attribute_session_secret_key(
        &mut self,
        old_key_share: PyAttributeSessionKeyShare,
        new_key_share: PyAttributeSessionKeyShare,
    ) {
        self.0
            .update_attribute_session_secret_key(old_key_share.0, new_key_share.0);
    }

    /// Update both pseudonym and attribute session key shares from one session to another.
    /// This is a convenience method that updates both shares together.
    #[pyo3(name = "update_session_secret_keys")]
    fn py_update_session_secret_keys(
        &mut self,
        old_key_shares: PySessionKeyShares,
        new_key_shares: PySessionKeyShares,
    ) {
        let old_shares = SessionKeyShares {
            pseudonym: PseudonymSessionKeyShare(old_key_shares.pseudonym.0 .0),
            attribute: AttributeSessionKeyShare(old_key_shares.attribute.0 .0),
        };
        let new_shares = SessionKeyShares {
            pseudonym: PseudonymSessionKeyShare(new_key_shares.pseudonym.0 .0),
            attribute: AttributeSessionKeyShare(new_key_shares.attribute.0 .0),
        };
        self.0.update_session_secret_keys(old_shares, new_shares);
    }

    /// Decrypt an encrypted pseudonym.
    #[pyo3(name = "decrypt_pseudonym")]
    fn py_decrypt_pseudonym(&self, encrypted: &PyEncryptedPseudonym) -> PyPseudonym {
        PyPseudonym::from(self.decrypt_pseudonym(&encrypted.0))
    }

    /// Decrypt an encrypted attribute.
    #[pyo3(name = "decrypt_data")]
    fn py_decrypt_data(&self, encrypted: &PyEncryptedAttribute) -> PyAttribute {
        PyAttribute::from(self.decrypt_attribute(&encrypted.0))
    }

    /// Encrypt an attribute with the session public key.
    #[pyo3(name = "encrypt_data")]
    fn py_encrypt_data(&self, message: &PyAttribute) -> PyEncryptedAttribute {
        let mut rng = rand::thread_rng();
        PyEncryptedAttribute::from(self.encrypt_attribute(&message.0, &mut rng))
    }

    /// Encrypt a pseudonym with the session public key.
    #[pyo3(name = "encrypt_pseudonym")]
    fn py_encrypt_pseudonym(&self, message: &PyPseudonym) -> PyEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        PyEncryptedPseudonym(self.encrypt_pseudonym(&message.0, &mut rng))
    }
}

/// An offline PEP client that can encrypt data, based on global public keys for pseudonyms and attributes.
/// This client is used for encryption only, and does not have session key pairs.
/// This can be useful when encryption is done offline and no session key pairs are available,
/// or when using a session key would leak information.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "OfflinePEPClient")]
pub struct PyOfflinePEPClient(OfflinePEPClient);

#[pymethods]
impl PyOfflinePEPClient {
    /// Create a new offline PEP client from the given global public keys.
    #[new]
    fn new(global_keys: &PyGlobalPublicKeys) -> Self {
        let global_keys = GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey(global_keys.pseudonym.0 .0),
            attribute: AttributeGlobalPublicKey(global_keys.attribute.0 .0),
        };
        Self(OfflinePEPClient::new(global_keys))
    }

    /// Encrypt an attribute with the global public key.
    #[pyo3(name = "encrypt_data")]
    fn py_encrypt_data(&self, message: &PyAttribute) -> PyEncryptedAttribute {
        let mut rng = rand::thread_rng();
        PyEncryptedAttribute::from(self.encrypt_attribute(&message.0, &mut rng))
    }

    /// Encrypt a pseudonym with the global public key.
    #[pyo3(name = "encrypt_pseudonym")]
    fn py_encrypt_pseudonym(&self, message: &PyPseudonym) -> PyEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        PyEncryptedPseudonym(self.encrypt_pseudonym(&message.0, &mut rng))
    }
}

// Missing types from high_level that are needed here
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[pyclass(name = "ReshuffleFactor")]
pub struct PyReshuffleFactor(ReshuffleFactor);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[pyclass(name = "PseudonymRekeyFactor")]
pub struct PyPseudonymRekeyFactor(PseudonymRekeyFactor);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[pyclass(name = "AttributeRekeyFactor")]
pub struct PyAttributeRekeyFactor(AttributeRekeyFactor);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "PseudonymRSKFactors")]
pub struct PyPseudonymRSKFactors {
    #[pyo3(get)]
    pub s: PyReshuffleFactor,
    #[pyo3(get)]
    pub k: PyPseudonymRekeyFactor,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymizationInfo")]
pub struct PyPseudonymizationInfo(pub PyPseudonymRSKFactors);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "AttributeRekeyInfo")]
pub struct PyAttributeRekeyInfo(pub PyAttributeRekeyFactor);

#[derive(Copy, Clone, Debug)]
#[pyclass(name = "TranscryptionInfo")]
pub struct PyTranscryptionInfo {
    #[pyo3(get)]
    pub pseudonym: PyPseudonymizationInfo,
    #[pyo3(get)]
    pub attribute: PyAttributeRekeyInfo,
}

#[pymethods]
impl PyPseudonymizationInfo {
    #[new]
    fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
        pseudonymization_secret: &PyPseudonymizationSecret,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        let x = PseudonymizationInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );
        let s = PyReshuffleFactor(x.s);
        let k = PyPseudonymRekeyFactor(x.k);
        PyPseudonymizationInfo(PyPseudonymRSKFactors { s, k })
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        PyPseudonymizationInfo(PyPseudonymRSKFactors {
            s: PyReshuffleFactor(ReshuffleFactor(self.0.s.0 .0.invert())),
            k: PyPseudonymRekeyFactor(PseudonymRekeyFactor(self.0.k.0 .0.invert())),
        })
    }
}

#[pymethods]
impl PyAttributeRekeyInfo {
    #[new]
    fn new(session_from: &str, session_to: &str, encryption_secret: &PyEncryptionSecret) -> Self {
        let x = AttributeRekeyInfo::new(
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &encryption_secret.0,
        );
        PyAttributeRekeyInfo(PyAttributeRekeyFactor(x))
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        PyAttributeRekeyInfo(PyAttributeRekeyFactor(AttributeRekeyFactor(
            self.0 .0 .0.invert(),
        )))
    }
}

#[pymethods]
impl PyTranscryptionInfo {
    #[new]
    fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
        pseudonymization_secret: &PyPseudonymizationSecret,
        encryption_secret: &PyEncryptionSecret,
    ) -> Self {
        let x = TranscryptionInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );
        Self {
            pseudonym: PyPseudonymizationInfo::from(x.pseudonym),
            attribute: PyAttributeRekeyInfo::from(x.attribute),
        }
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        Self {
            pseudonym: self.pseudonym.rev(),
            attribute: self.attribute.rev(),
        }
    }
}

impl From<PseudonymizationInfo> for PyPseudonymizationInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        let s = PyReshuffleFactor(x.s);
        let k = PyPseudonymRekeyFactor(x.k);
        PyPseudonymizationInfo(PyPseudonymRSKFactors { s, k })
    }
}

impl From<&PyPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &PyPseudonymizationInfo) -> Self {
        let s = x.s.0;
        let k = x.k.0;
        PseudonymizationInfo { s, k }
    }
}

impl From<AttributeRekeyInfo> for PyAttributeRekeyInfo {
    fn from(x: AttributeRekeyInfo) -> Self {
        PyAttributeRekeyInfo(PyAttributeRekeyFactor(x))
    }
}

impl From<&PyAttributeRekeyInfo> for AttributeRekeyInfo {
    fn from(x: &PyAttributeRekeyInfo) -> Self {
        x.0 .0
    }
}

impl From<TranscryptionInfo> for PyTranscryptionInfo {
    fn from(x: TranscryptionInfo) -> Self {
        Self {
            pseudonym: PyPseudonymizationInfo::from(x.pseudonym),
            attribute: PyAttributeRekeyInfo::from(x.attribute),
        }
    }
}

impl From<&PyTranscryptionInfo> for TranscryptionInfo {
    fn from(x: &PyTranscryptionInfo) -> Self {
        Self {
            pseudonym: PseudonymizationInfo::from(&x.pseudonym),
            attribute: AttributeRekeyInfo::from(&x.attribute),
        }
    }
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBlindingFactor>()?;
    m.add_class::<PyBlindedPseudonymGlobalSecretKey>()?;
    m.add_class::<PyBlindedAttributeGlobalSecretKey>()?;
    m.add_class::<PyPseudonymSessionKeyShare>()?;
    m.add_class::<PyAttributeSessionKeyShare>()?;
    m.add_class::<PySessionKeyShares>()?;
    m.add_class::<PyBlindedGlobalKeys>()?;
    m.add_class::<PySessionPublicKeys>()?;
    m.add_class::<PySessionSecretKeys>()?;
    m.add_class::<PySessionKeys>()?;
    m.add_class::<PyPEPSystem>()?;
    m.add_class::<PyPEPClient>()?;
    m.add_class::<PyOfflinePEPClient>()?;
    m.add_class::<PyReshuffleFactor>()?;
    m.add_class::<PyPseudonymRekeyFactor>()?;
    m.add_class::<PyAttributeRekeyFactor>()?;
    m.add_class::<PyPseudonymRSKFactors>()?;
    m.add_class::<PyPseudonymizationInfo>()?;
    m.add_class::<PyAttributeRekeyInfo>()?;
    m.add_class::<PyTranscryptionInfo>()?;
    m.add_function(wrap_pyfunction!(
        py_make_blinded_pseudonym_global_secret_key,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        py_make_blinded_attribute_global_secret_key,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(py_make_blinded_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_key_share, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_key_share, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_key_shares, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_keys_distributed, m)?)?;
    m.add_function(wrap_pyfunction!(py_update_pseudonym_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_update_attribute_session_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_update_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(
        py_make_distributed_pseudonym_global_keys,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        py_make_distributed_attribute_global_keys,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(py_make_distributed_global_keys, m)?)?;
    Ok(())
}
