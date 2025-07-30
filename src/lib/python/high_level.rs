use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::internal::arithmetic::GroupElement;
use crate::python::arithmetic::{PyGroupElement, PyScalarNonZero};
use crate::python::elgamal::PyElGamal;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// A session secret key used to decrypt messages with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "SessionSecretKey")]
pub struct PySessionSecretKey(pub PyScalarNonZero);

/// A global secret key from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[pyclass(name = "GlobalSecretKey")]
pub struct PyGlobalSecretKey(pub PyScalarNonZero);

/// A session public key used to encrypt messages against, associated with a [`PySessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "SessionPublicKey")]
pub struct PySessionPublicKey(pub PyGroupElement);

#[pymethods]
impl PySessionPublicKey {
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

/// A global public key associated with the [`PyGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt messages against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, From)]
#[pyclass(name = "GlobalPublicKey")]
pub struct PyGlobalPublicKey(pub PyGroupElement);

#[pymethods]
impl PyGlobalPublicKey {
    /// Creates a new global public key from a group element.
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
        format!("GlobalPublicKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }
}

/// Pseudonymization secret used to derive a [`PyReshuffleFactor`] from a pseudonymization domain (see [`PyPseudonymizationInfo`]).
/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from domains and sessions.
#[derive(Clone, Debug, From)]
#[pyclass(name = "PseudonymizationSecret")]
pub struct PyPseudonymizationSecret(pub(crate) PseudonymizationSecret);

/// Encryption secret used to derive a [`PyRekeyFactor`] from an encryption context (see [`PyRekeyInfo`]).
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
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
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
    fn as_bytes(&self, py: Python) -> Option<PyObject> {
        self.0.as_bytes().map(|x| PyBytes::new_bound(py, &x).into())
    }

    /// Create a collection of pseudonyms from an arbitrary-length string
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[staticmethod]
    #[pyo3(name = "from_string_padded")]
    fn from_string_padded(text: &str) -> Vec<PyPseudonym> {
        Pseudonym::from_string_padded(text)
            .into_iter()
            .map(PyPseudonym::from)
            .collect()
    }

    /// Create a collection of pseudonyms from an arbitrary-length byte array
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> Vec<PyPseudonym> {
        Pseudonym::from_bytes_padded(data)
            .into_iter()
            .map(PyPseudonym::from)
            .collect()
    }

    /// Convert a collection of pseudonyms back to the original string
    /// Returns null if the decoding fails (e.g., invalid padding or UTF-8)
    #[staticmethod]
    #[pyo3(name = "to_string_padded")]
    fn to_string_padded(pseudonyms: Vec<PyPseudonym>) -> PyResult<String> {
        let rust_pseudonyms: Vec<Pseudonym> = pseudonyms.into_iter().map(|p| p.0).collect();
        Pseudonym::to_string_padded(&rust_pseudonyms)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
    }

    /// Convert a collection of pseudonyms back to the original byte array
    /// Returns null if the decoding fails (e.g., invalid padding)
    #[staticmethod]
    #[pyo3(name = "to_bytes_padded")]
    fn to_bytes_padded(pseudonyms: Vec<PyPseudonym>, py: Python) -> PyResult<PyObject> {
        let rust_pseudonyms: Vec<Pseudonym> = pseudonyms.into_iter().map(|p| p.0).collect();
        let result = Pseudonym::to_bytes_padded(&rust_pseudonyms).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
        })?;
        Ok(PyBytes::new_bound(py, &result).into())
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

/// A data point which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[pyclass(name = "DataPoint")]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyDataPoint(pub(crate) DataPoint);

#[pymethods]
impl PyDataPoint {
    /// Create from a [`PyGroupElement`].
    #[new]
    fn new(x: PyGroupElement) -> Self {
        Self(DataPoint::from_point(x.0))
    }

    /// Convert to a [`PyGroupElement`].
    #[pyo3(name = "to_point")]
    fn to_point(&self) -> PyGroupElement {
        self.0.value.into()
    }

    /// Generate a random data point.
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self(DataPoint::random(&mut rng))
    }

    /// Encode the data point as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
    }

    /// Encode the data point as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a data point from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<Self> {
        DataPoint::decode_from_slice(bytes).map(Self)
    }

    /// Decode a data point from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<Self> {
        DataPoint::decode_from_hex(hex).map(Self)
    }

    /// Decode a data point from a 64-byte hash value
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
        Ok(DataPoint::from_hash(&arr).into())
    }

    /// Decode from a byte array of length 16.
    /// This is useful for encoding data points,
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
        Ok(Self(DataPoint::from_bytes(&arr)))
    }

    /// Encode as a byte array of length 16.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`PyDataPoint::from_bytes`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[pyo3(name = "as_bytes")]
    fn as_bytes(&self, py: Python) -> Option<PyObject> {
        self.0.as_bytes().map(|x| PyBytes::new_bound(py, &x).into())
    }

    /// Create a collection of data points from an arbitrary-length string
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[staticmethod]
    #[pyo3(name = "from_string_padded")]
    fn from_string_padded(text: &str) -> Vec<PyDataPoint> {
        DataPoint::from_string_padded(text)
            .into_iter()
            .map(PyDataPoint::from)
            .collect()
    }

    /// Create a collection of data points from an arbitrary-length byte array
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[staticmethod]
    #[pyo3(name = "from_bytes_padded")]
    fn from_bytes_padded(data: &[u8]) -> Vec<PyDataPoint> {
        DataPoint::from_bytes_padded(data)
            .into_iter()
            .map(PyDataPoint::from)
            .collect()
    }

    /// Convert a collection of data points back to the original string
    /// Returns null if the decoding fails (e.g., invalid padding or UTF-8)
    #[staticmethod]
    #[pyo3(name = "to_string_padded")]
    fn to_string_padded(data_points: Vec<PyDataPoint>) -> PyResult<String> {
        let rust_data_points: Vec<DataPoint> = data_points.into_iter().map(|p| p.0).collect();
        DataPoint::to_string_padded(&rust_data_points)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}")))
    }

    /// Convert a collection of data points back to the original byte array
    /// Returns null if the decoding fails (e.g., invalid padding)
    #[staticmethod]
    #[pyo3(name = "to_bytes_padded")]
    fn to_bytes_padded(data_points: Vec<PyDataPoint>, py: Python) -> PyResult<PyObject> {
        let rust_data_points: Vec<DataPoint> = data_points.into_iter().map(|p| p.0).collect();
        let result = DataPoint::to_bytes_padded(&rust_data_points).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
        })?;
        Ok(PyBytes::new_bound(py, &result).into())
    }

    fn __repr__(&self) -> String {
        format!("DataPoint({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyDataPoint) -> bool {
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
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
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

/// An encrypted data point, which is an [`PyElGamal`] encryption of a [`PyDataPoint`].
#[pyclass(name = "EncryptedDataPoint")]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyEncryptedDataPoint(pub(crate) EncryptedDataPoint);

#[pymethods]
impl PyEncryptedDataPoint {
    /// Create from an [`PyElGamal`].
    #[new]
    fn new(x: PyElGamal) -> Self {
        Self(EncryptedDataPoint::from(x.0))
    }

    /// Encode the encrypted data point as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
    }

    /// Decode an encrypted data point from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(v: &[u8]) -> Option<Self> {
        EncryptedDataPoint::decode_from_slice(v).map(Self)
    }

    /// Encode the encrypted data point as a base64 string.
    #[pyo3(name = "as_base64")]
    fn as_base64(&self) -> String {
        self.encode_as_base64()
    }

    /// Decode an encrypted data point from a base64 string.
    #[staticmethod]
    #[pyo3(name = "from_base64")]
    fn from_base64(s: &str) -> Option<Self> {
        EncryptedDataPoint::from_base64(s).map(Self)
    }

    fn __repr__(&self) -> String {
        format!("EncryptedDataPoint({})", self.as_base64())
    }

    fn __str__(&self) -> String {
        self.as_base64()
    }

    fn __eq__(&self, other: &PyEncryptedDataPoint) -> bool {
        self.0 == other.0
    }
}

// Global key pair
#[pyclass(name = "GlobalKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PyGlobalKeyPair {
    #[pyo3(get)]
    pub public: PyGlobalPublicKey,
    #[pyo3(get)]
    pub secret: PyGlobalSecretKey,
}

// Session key pair
#[pyclass(name = "SessionKeyPair")]
#[derive(Copy, Clone, Debug)]
pub struct PySessionKeyPair {
    #[pyo3(get)]
    pub public: PySessionPublicKey,
    #[pyo3(get)]
    pub secret: PySessionSecretKey,
}

/// Generate a new global key pair.
#[pyfunction]
#[pyo3(name = "make_global_keys")]
pub fn py_make_global_keys() -> PyGlobalKeyPair {
    let mut rng = rand::thread_rng();
    let (public, secret) = make_global_keys(&mut rng);
    PyGlobalKeyPair {
        public: PyGlobalPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyGlobalSecretKey::from(PyScalarNonZero::from(secret.0)),
    }
}

/// Generate session keys from a [`PyGlobalSecretKey`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_session_keys")]
pub fn py_make_session_keys(
    global: &PyGlobalSecretKey,
    session: &str,
    secret: &PyEncryptionSecret,
) -> PySessionKeyPair {
    let (public, secret) = make_session_keys(
        &GlobalSecretKey(global.0 .0),
        &EncryptionContext::from(session),
        &secret.0,
    );
    PySessionKeyPair {
        public: PySessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PySessionSecretKey::from(PyScalarNonZero::from(secret.0)),
    }
}

/// Encrypt a pseudonym using a session public key.
#[pyfunction]
#[pyo3(name = "encrypt_pseudonym")]
pub fn py_encrypt_pseudonym(
    message: &PyPseudonym,
    public_key: &PySessionPublicKey,
) -> PyEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    PyEncryptedPseudonym(encrypt(
        &message.0,
        &SessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt an encrypted pseudonym using a session secret key.
#[pyfunction]
#[pyo3(name = "decrypt_pseudonym")]
pub fn py_decrypt_pseudonym(
    encrypted: &PyEncryptedPseudonym,
    secret_key: &PySessionSecretKey,
) -> PyPseudonym {
    PyPseudonym(decrypt(
        &encrypted.0,
        &SessionSecretKey::from(secret_key.0 .0),
    ))
}

/// Encrypt a data point using a session public key.
#[pyfunction]
#[pyo3(name = "encrypt_data")]
pub fn py_encrypt_data(
    message: &PyDataPoint,
    public_key: &PySessionPublicKey,
) -> PyEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    PyEncryptedDataPoint(encrypt(
        &message.0,
        &SessionPublicKey::from(public_key.0 .0),
        &mut rng,
    ))
}

/// Decrypt an encrypted data point using a session secret key.
#[pyfunction]
#[pyo3(name = "decrypt_data")]
pub fn py_decrypt_data(
    encrypted: &PyEncryptedDataPoint,
    secret_key: &PySessionSecretKey,
) -> PyDataPoint {
    PyDataPoint(decrypt(
        &EncryptedDataPoint::from(encrypted.value),
        &SessionSecretKey::from(secret_key.0 .0),
    ))
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySessionSecretKey>()?;
    m.add_class::<PyGlobalSecretKey>()?;
    m.add_class::<PySessionPublicKey>()?;
    m.add_class::<PyGlobalPublicKey>()?;
    m.add_class::<PyPseudonymizationSecret>()?;
    m.add_class::<PyEncryptionSecret>()?;
    m.add_class::<PyPseudonym>()?;
    m.add_class::<PyDataPoint>()?;
    m.add_class::<PyEncryptedPseudonym>()?;
    m.add_class::<PyEncryptedDataPoint>()?;
    m.add_class::<PyGlobalKeyPair>()?;
    m.add_class::<PySessionKeyPair>()?;
    m.add_function(wrap_pyfunction!(py_make_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_pseudonym, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_data, m)?)?;
    Ok(())
}
