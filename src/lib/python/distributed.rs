use crate::distributed::key_blinding::*;
use crate::distributed::systems::*;
use crate::high_level::contexts::*;
use crate::high_level::keys::*;
use crate::python::arithmetic::*;
use crate::python::high_level::*;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

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
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
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

/// A blinded global secret key, which is the global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "BlindedGlobalSecretKey")]
pub struct PyBlindedGlobalSecretKey(BlindedGlobalSecretKey);

#[pymethods]
impl PyBlindedGlobalSecretKey {
    /// Create a new [`PyBlindedGlobalSecretKey`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyBlindedGlobalSecretKey(BlindedGlobalSecretKey(x.0))
    }

    /// Encode the [`PyBlindedGlobalSecretKey`] as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
    }

    /// Decode a [`PyBlindedGlobalSecretKey`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PyBlindedGlobalSecretKey> {
        BlindedGlobalSecretKey::decode_from_slice(bytes).map(PyBlindedGlobalSecretKey)
    }

    /// Encode the [`PyBlindedGlobalSecretKey`] as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a [`PyBlindedGlobalSecretKey`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyBlindedGlobalSecretKey> {
        BlindedGlobalSecretKey::decode_from_hex(hex).map(PyBlindedGlobalSecretKey)
    }

    fn __repr__(&self) -> String {
        format!("BlindedGlobalSecretKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyBlindedGlobalSecretKey) -> bool {
        self.0 == other.0
    }
}

/// A session key share, which a part a session key provided by one transcryptor.
/// By combining all session key shares and the [`PyBlindedGlobalSecretKey`], a session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "SessionKeyShare")]
pub struct PySessionKeyShare(SessionKeyShare);

#[pymethods]
impl PySessionKeyShare {
    /// Create a new [`PySessionKeyShare`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PySessionKeyShare(SessionKeyShare(x.0))
    }

    /// Encode the [`PySessionKeyShare`] as a byte array.
    #[pyo3(name = "encode")]
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
    }

    /// Decode a [`PySessionKeyShare`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "decode")]
    fn decode(bytes: &[u8]) -> Option<PySessionKeyShare> {
        SessionKeyShare::decode_from_slice(bytes).map(PySessionKeyShare)
    }

    /// Encode the [`PySessionKeyShare`] as a hexadecimal string.
    #[pyo3(name = "as_hex")]
    fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    /// Decode a [`PySessionKeyShare`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PySessionKeyShare> {
        SessionKeyShare::decode_from_hex(hex).map(PySessionKeyShare)
    }

    fn __repr__(&self) -> String {
        format!("SessionKeyShare({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PySessionKeyShare) -> bool {
        self.0 == other.0
    }
}

/// Create a [`PyBlindedGlobalSecretKey`] from a [`PyPseudonymGlobalSecretKey`] and a list of [`PyBlindingFactor`]s.
/// Used during system setup to blind the pseudonym global secret key.
/// Returns an error if the product of all blinding factors accidentally turns out to be 1.
#[pyfunction]
#[pyo3(name = "make_blinded_pseudonym_global_secret_key")]
pub fn py_make_blinded_pseudonym_global_secret_key(
    global_secret_key: &PyPseudonymGlobalSecretKey,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_global_pseudonym_secret_key(
        &PseudonymGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedGlobalSecretKey(result))
}

/// Create a [`PyBlindedGlobalSecretKey`] from a [`PyAttributeGlobalSecretKey`] and a list of [`PyBlindingFactor`]s.
/// Used during system setup to blind the attribute global secret key.
/// Returns an error if the product of all blinding factors accidentally turns out to be 1.
#[pyfunction]
#[pyo3(name = "make_blinded_attribute_global_secret_key")]
pub fn py_make_blinded_attribute_global_secret_key(
    global_secret_key: &PyAttributeGlobalSecretKey,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_global_attribute_secret_key(
        &AttributeGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedGlobalSecretKey(result))
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

    /// Generate a session key share for the given session.
    #[pyo3(name = "session_key_share")]
    fn py_session_key_share(&self, session: &str) -> PySessionKeyShare {
        PySessionKeyShare(self.session_key_share(&EncryptionContext::from(session)))
    }

    /// Generate a rekey info to rekey from a given session to another.
    #[pyo3(name = "rekey_info")]
    fn py_rekey_info(&self, session_from: &str, session_to: &str) -> PyRekeyInfo {
        PyRekeyInfo::from(self.rekey_info(
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
        ))
    }

    /// Generate a pseudonymization info to pseudonymize from a given pseudonymization domain
    /// and session to another.
    #[pyo3(name = "pseudonymization_info")]
    fn py_pseudonymization_info(
        &self,
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
    ) -> PyPseudonymizationInfo {
        PyPseudonymizationInfo::from(self.pseudonymization_info(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
        ))
    }

    /// Rekey an [`PyEncryptedAttribute`] from one session to another, using [`PyRekeyInfo`].
    #[pyo3(name = "rekey")]
    fn py_rekey(
        &self,
        encrypted: &PyEncryptedAttribute,
        rekey_info: &PyRekeyInfo,
    ) -> PyEncryptedAttribute {
        PyEncryptedAttribute::from(self.rekey(&encrypted.0, &RekeyInfo::from(rekey_info)))
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
}

/// A PEP client that can encrypt and decrypt data, based on separate session key pairs for pseudonyms and attributes.
#[derive(Clone, From, Into, Deref)]
#[pyclass(name = "PEPClient")]
pub struct PyPEPClient(PEPClient);

#[pymethods]
impl PyPEPClient {
    /// Create a new PEP client from the given session key shares for both pseudonyms and attributes.
    #[new]
    fn new(
        blinded_global_pseudonym_key: &PyBlindedGlobalSecretKey,
        pseudonym_session_key_shares: Vec<PySessionKeyShare>,
        blinded_global_attribute_key: &PyBlindedGlobalSecretKey,
        attribute_session_key_shares: Vec<PySessionKeyShare>,
    ) -> Self {
        let pseudonym_shares: Vec<SessionKeyShare> = pseudonym_session_key_shares
            .into_iter()
            .map(|x| SessionKeyShare(x.0 .0))
            .collect();
        let attribute_shares: Vec<SessionKeyShare> = attribute_session_key_shares
            .into_iter()
            .map(|x| SessionKeyShare(x.0 .0))
            .collect();
        Self(PEPClient::new(
            blinded_global_pseudonym_key.0,
            &pseudonym_shares,
            blinded_global_attribute_key.0,
            &attribute_shares,
        ))
    }

    /// Restore a PEP client from the given session keys.
    #[staticmethod]
    #[pyo3(name = "restore")]
    fn py_restore(
        pseudonym_session_keys: &PyPseudonymSessionKeyPair,
        attribute_session_keys: &PyAttributeSessionKeyPair,
    ) -> Self {
        Self(PEPClient::restore(
            PseudonymSessionPublicKey(pseudonym_session_keys.public.0 .0),
            PseudonymSessionSecretKey(pseudonym_session_keys.secret.0 .0),
            AttributeSessionPublicKey(attribute_session_keys.public.0 .0),
            AttributeSessionSecretKey(attribute_session_keys.secret.0 .0),
        ))
    }

    /// Dump the pseudonym session key pair.
    #[pyo3(name = "dump_pseudonym_keys")]
    fn py_dump_pseudonym_keys(&self) -> PyPseudonymSessionKeyPair {
        PyPseudonymSessionKeyPair {
            public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(
                self.pseudonym_session_public_key.0,
            )),
            secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(
                self.pseudonym_session_secret_key.0,
            )),
        }
    }

    /// Dump the attribute session key pair.
    #[pyo3(name = "dump_attribute_keys")]
    fn py_dump_attribute_keys(&self) -> PyAttributeSessionKeyPair {
        PyAttributeSessionKeyPair {
            public: PyAttributeSessionPublicKey::from(PyGroupElement::from(
                self.attribute_session_public_key.0,
            )),
            secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(
                self.attribute_session_secret_key.0,
            )),
        }
    }

    /// Update a pseudonym session key share from one session to the other
    #[pyo3(name = "update_pseudonym_session_secret_key")]
    fn py_update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: PySessionKeyShare,
        new_key_share: PySessionKeyShare,
    ) {
        self.0
            .update_pseudonym_session_secret_key(old_key_share.0, new_key_share.0);
    }

    /// Update an attribute session key share from one session to the other
    #[pyo3(name = "update_attribute_session_secret_key")]
    fn py_update_attribute_session_secret_key(
        &mut self,
        old_key_share: PySessionKeyShare,
        new_key_share: PySessionKeyShare,
    ) {
        self.0
            .update_attribute_session_secret_key(old_key_share.0, new_key_share.0);
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
    fn new(
        global_pseudonym_public_key: PyPseudonymGlobalPublicKey,
        global_attribute_public_key: PyAttributeGlobalPublicKey,
    ) -> Self {
        Self(OfflinePEPClient::new(
            PseudonymGlobalPublicKey(global_pseudonym_public_key.0 .0),
            AttributeGlobalPublicKey(global_attribute_public_key.0 .0),
        ))
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
#[pyclass(name = "RekeyFactor")]
pub struct PyRekeyFactor(RekeyFactor);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "RSKFactors")]
pub struct PyRSKFactors {
    #[pyo3(get)]
    pub s: PyReshuffleFactor,
    #[pyo3(get)]
    pub k: PyRekeyFactor,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "PseudonymizationInfo")]
pub struct PyPseudonymizationInfo(pub PyRSKFactors);

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "RekeyInfo")]
pub struct PyRekeyInfo(pub PyRekeyFactor);

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
        let k = PyRekeyFactor(x.k);
        PyPseudonymizationInfo(PyRSKFactors { s, k })
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        PyPseudonymizationInfo(PyRSKFactors {
            s: PyReshuffleFactor(ReshuffleFactor(self.0.s.0 .0.invert())),
            k: PyRekeyFactor(RekeyFactor(self.0.k.0 .0.invert())),
        })
    }
}

#[pymethods]
impl PyRekeyInfo {
    #[new]
    fn new(session_from: &str, session_to: &str, encryption_secret: &PyEncryptionSecret) -> Self {
        let x = RekeyInfo::new(
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &encryption_secret.0,
        );
        PyRekeyInfo(PyRekeyFactor(x))
    }

    #[pyo3(name = "rev")]
    fn rev(&self) -> Self {
        PyRekeyInfo(PyRekeyFactor(RekeyFactor(self.0 .0 .0.invert())))
    }

    #[staticmethod]
    #[pyo3(name = "from_pseudo_info")]
    fn from_pseudo_info(x: &PyPseudonymizationInfo) -> Self {
        PyRekeyInfo(x.0.k)
    }
}

impl From<PseudonymizationInfo> for PyPseudonymizationInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        let s = PyReshuffleFactor(x.s);
        let k = PyRekeyFactor(x.k);
        PyPseudonymizationInfo(PyRSKFactors { s, k })
    }
}

impl From<&PyPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &PyPseudonymizationInfo) -> Self {
        let s = x.s.0;
        let k = x.k.0;
        PseudonymizationInfo { s, k }
    }
}

impl From<RekeyInfo> for PyRekeyInfo {
    fn from(x: RekeyInfo) -> Self {
        PyRekeyInfo(PyRekeyFactor(x))
    }
}

impl From<&PyRekeyInfo> for RekeyInfo {
    fn from(x: &PyRekeyInfo) -> Self {
        x.0 .0
    }
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBlindingFactor>()?;
    m.add_class::<PyBlindedGlobalSecretKey>()?;
    m.add_class::<PySessionKeyShare>()?;
    m.add_class::<PyPEPSystem>()?;
    m.add_class::<PyPEPClient>()?;
    m.add_class::<PyOfflinePEPClient>()?;
    m.add_class::<PyReshuffleFactor>()?;
    m.add_class::<PyRekeyFactor>()?;
    m.add_class::<PyRSKFactors>()?;
    m.add_class::<PyPseudonymizationInfo>()?;
    m.add_class::<PyRekeyInfo>()?;
    m.add_function(wrap_pyfunction!(
        py_make_blinded_pseudonym_global_secret_key,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        py_make_blinded_attribute_global_secret_key,
        m
    )?)?;
    Ok(())
}
