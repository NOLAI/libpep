use crate::distributed::key_blinding::*;
use crate::distributed::systems::*;
use crate::high_level::contexts::*;
use crate::high_level::keys::*;
use crate::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
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
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
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
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
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
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
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
    fn encode(&self, py: Python) -> PyObject {
        PyBytes::new_bound(py, &self.0.encode()).into()
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

/// Create a [`PyBlindedPseudonymGlobalSecretKey`] from a [`PyPseudonymGlobalSecretKey`] and a list of [`PyBlindingFactor`]s.
/// Used during system setup to blind the pseudonym global secret key.
/// Returns an error if the product of all blinding factors accidentally turns out to be 1.
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

/// Create a [`PyBlindedAttributeGlobalSecretKey`] from a [`PyAttributeGlobalSecretKey`] and a list of [`PyBlindingFactor`]s.
/// Used during system setup to blind the attribute global secret key.
/// Returns an error if the product of all blinding factors accidentally turns out to be 1.
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
    #[pyo3(name = "attribute_rekey_info")]
    fn py_attribute_rekey_info(
        &self,
        session_from: &str,
        session_to: &str,
    ) -> PyAttributeRekeyInfo {
        PyAttributeRekeyInfo::from(self.attribute_rekey_info(
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
        blinded_global_pseudonym_key: &PyBlindedPseudonymGlobalSecretKey,
        pseudonym_session_key_shares: Vec<PyPseudonymSessionKeyShare>,
        blinded_global_attribute_key: &PyBlindedAttributeGlobalSecretKey,
        attribute_session_key_shares: Vec<PyAttributeSessionKeyShare>,
    ) -> Self {
        let pseudonym_shares: Vec<PseudonymSessionKeyShare> = pseudonym_session_key_shares
            .into_iter()
            .map(|x| PseudonymSessionKeyShare(x.0 .0))
            .collect();
        let attribute_shares: Vec<AttributeSessionKeyShare> = attribute_session_key_shares
            .into_iter()
            .map(|x| AttributeSessionKeyShare(x.0 .0))
            .collect();
        Self(PEPClient::new(
            blinded_global_pseudonym_key.0,
            &pseudonym_shares,
            blinded_global_attribute_key.0,
            &attribute_shares,
        ))
    }

    /// Create a new PEP client from combined session key shares.
    /// This is a convenience method that accepts a list of [`PySessionKeyShares`].
    #[staticmethod]
    #[pyo3(name = "from_session_key_shares")]
    fn py_from_session_key_shares(
        blinded_global_pseudonym_key: &PyBlindedPseudonymGlobalSecretKey,
        blinded_global_attribute_key: &PyBlindedAttributeGlobalSecretKey,
        session_key_shares: Vec<PySessionKeyShares>,
    ) -> Self {
        let shares: Vec<SessionKeyShares> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShares {
                pseudonym: PseudonymSessionKeyShare(x.pseudonym.0 .0),
                attribute: AttributeSessionKeyShare(x.attribute.0 .0),
            })
            .collect();
        Self(PEPClient::from_session_key_shares(
            blinded_global_pseudonym_key.0,
            blinded_global_attribute_key.0,
            &shares,
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
    Ok(())
}
