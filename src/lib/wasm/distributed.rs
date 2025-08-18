use crate::distributed::key_blinding::*;
use crate::distributed::systems::*;
use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::internal::arithmetic::ScalarNonZero;
use crate::wasm::arithmetic::*;
use crate::wasm::high_level::*;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindingFactor)]
pub struct WASMBlindingFactor(BlindingFactor);

#[wasm_bindgen(js_class = "BlindingFactor")]
impl WASMBlindingFactor {
    /// Create a new [`WASMBlindingFactor`] from a [`WASMScalarNonZero`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindingFactor(BlindingFactor(x.0))
    }
    /// Generate a random [`WASMBlindingFactor`].
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let x = BlindingFactor::random(&mut rng);
        WASMBlindingFactor(x)
    }
    /// Clone the [`WASMBlindingFactor`].
    #[wasm_bindgen(js_name = clone)]
    pub fn clone_js(&self) -> Self {
        WASMBlindingFactor(self.0)
    }
    /// Encode the [`WASMBlindingFactor`] as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode a [`WASMBlindingFactor`] from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMBlindingFactor> {
        BlindingFactor::decode_from_slice(bytes.as_slice()).map(WASMBlindingFactor)
    }
    /// Encode the [`WASMBlindingFactor`] as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a [`WASMBlindingFactor`] from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindingFactor> {
        BlindingFactor::decode_from_hex(hex).map(WASMBlindingFactor)
    }
}

/// A blinded global secret key, which is the global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedGlobalSecretKey)]
pub struct WASMBlindedGlobalSecretKey(BlindedGlobalSecretKey);

#[wasm_bindgen(js_class = "BlindedGlobalSecretKey")]
impl WASMBlindedGlobalSecretKey {
    /// Create a new [`WASMBlindedGlobalSecretKey`] from a [`WASMScalarNonZero`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindedGlobalSecretKey(BlindedGlobalSecretKey(x.0))
    }

    /// Encode the [`WASMBlindedGlobalSecretKey`] as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode a [`WASMBlindedGlobalSecretKey`] from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMBlindedGlobalSecretKey> {
        BlindedGlobalSecretKey::decode_from_slice(bytes.as_slice()).map(WASMBlindedGlobalSecretKey)
    }
    /// Encode the [`WASMBlindedGlobalSecretKey`] as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a [`WASMBlindedGlobalSecretKey`] from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindedGlobalSecretKey> {
        BlindedGlobalSecretKey::decode_from_hex(hex).map(WASMBlindedGlobalSecretKey)
    }
}

/// A session key share, which a part a session key provided by one transcryptor.
/// By combining all session key shares and the [`WASMBlindedGlobalSecretKey`], a session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionKeyShare)]
pub struct WASMSessionKeyShare(SessionKeyShare);

#[wasm_bindgen(js_class = "SessionKeyShare")]
impl WASMSessionKeyShare {
    /// Create a new [`WASMSessionKeyShare`] from a [`WASMScalarNonZero`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMSessionKeyShare(SessionKeyShare(x.0))
    }
    /// Encode the [`WASMSessionKeyShare`] as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode a [`WASMSessionKeyShare`] from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMSessionKeyShare> {
        SessionKeyShare::decode_from_slice(bytes.as_slice()).map(WASMSessionKeyShare)
    }
    /// Encode the [`WASMSessionKeyShare`] as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a [`WASMSessionKeyShare`] from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMSessionKeyShare> {
        SessionKeyShare::decode_from_hex(hex).map(WASMSessionKeyShare)
    }
}

/// Create a [`WASMBlindedGlobalSecretKey`] from a [`WASMGlobalSecretKey`] and a list of [`WASMBlindingFactor`]s.
/// Used during system setup to blind the global secret key.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
#[wasm_bindgen(js_name = makeBlindedGlobalSecretKey)]
pub fn wasm_make_blinded_global_secret_key(
    global_secret_key: &WASMGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> WASMBlindedGlobalSecretKey {
    // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
    // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
    // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    WASMBlindedGlobalSecretKey(
        make_blinded_global_secret_key(
            &GlobalSecretKey::from(ScalarNonZero::from(global_secret_key.0)),
            &bs,
        )
        .unwrap(),
    )
}

/// A PEP transcryptor system that can [pseudonymize] and [rekey] data, based on
/// a pseudonymisation secret, a rekeying secret and a blinding factor.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PEPSystem)]
pub struct WASMPEPSystem(PEPSystem);

#[wasm_bindgen(js_class = PEPSystem)]
impl WASMPEPSystem {
    /// Create a new PEP system with the given secrets and blinding factor.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonymisation_secret: &str,
        rekeying_secret: &str,
        blinding_factor: &WASMBlindingFactor,
    ) -> Self {
        Self(PEPSystem::new(
            PseudonymizationSecret::from(pseudonymisation_secret.as_bytes().into()),
            EncryptionSecret::from(rekeying_secret.as_bytes().into()),
            BlindingFactor(blinding_factor.0 .0),
        ))
    }
    /// Generate a session key share for the given session.
    #[wasm_bindgen(js_name = sessionKeyShare)]
    pub fn wasm_session_key_share(&self, session: &str) -> WASMSessionKeyShare {
        WASMSessionKeyShare(self.session_key_share(&EncryptionContext::from(session)))
    }
    /// Generate a rekey info to rekey from a given session to another.
    #[wasm_bindgen(js_name = rekeyInfo)]
    pub fn wasm_rekey_info(&self, session_from: &str, session_to: &str) -> WASMRekeyInfo {
        WASMRekeyInfo::from(self.rekey_info(
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
        ))
    }
    /// Generate a pseudonymization info to pseudonymize from a given pseudonymization domain
    /// and session to another.
    #[wasm_bindgen(js_name = pseudonymizationInfo)]
    pub fn wasm_pseudonymization_info(
        &self,
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
    ) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo::from(self.pseudonymization_info(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
        ))
    }

    /// Rekey an [`WASMEncryptedDataPoint`] from one session to another, using [`WASMRekeyInfo`].
    #[wasm_bindgen(js_name = rekey)]
    pub fn wasm_rekey(
        &self,
        encrypted: &WASMEncryptedDataPoint,
        rekey_info: &WASMRekeyInfo,
    ) -> WASMEncryptedDataPoint {
        WASMEncryptedDataPoint::from(self.rekey(&encrypted.0, &RekeyInfo::from(rekey_info)))
    }

    /// Pseudonymize an [`WASMEncryptedPseudonym`] from one pseudonymization domain and session to
    /// another, using [`WASMPseudonymizationInfo`].
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> WASMEncryptedPseudonym {
        WASMEncryptedPseudonym::from(
            self.pseudonymize(&encrypted.0, &PseudonymizationInfo::from(pseudo_info)),
        )
    }
}
/// A PEP client that can encrypt and decrypt data, based on a session key pair.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PEPClient)]
pub struct WASMPEPClient(PEPClient);
#[wasm_bindgen(js_class = PEPClient)]
impl WASMPEPClient {
    /// Create a new PEP client from the given session key shares.
    #[wasm_bindgen(constructor)]
    pub fn new(
        blinded_global_private_key: &WASMBlindedGlobalSecretKey,
        session_key_shares: Vec<WASMSessionKeyShare>,
    ) -> Self {
        // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
        // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
        // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
        let session_key_shares: Vec<SessionKeyShare> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShare(x.0 .0))
            .collect();
        let blinded_key = blinded_global_private_key.0;
        Self(PEPClient::new(
            BlindedGlobalSecretKey(blinded_key.0),
            &session_key_shares,
        ))
    }

    /// Restore a PEP client from the given session keys.
    #[wasm_bindgen(js_name = restore)]
    pub fn wasm_restore(session_keys: &WASMSessionKeyPair) -> Self {
        Self(PEPClient::restore(
            SessionPublicKey(**session_keys.public),
            SessionSecretKey(**session_keys.secret),
        ))
    }

    /// Dump the session key pair.
    #[wasm_bindgen(js_name = dump)]
    pub fn wasm_dump(&self) -> WASMSessionKeyPair {
        WASMSessionKeyPair {
            public: WASMSessionPublicKey::from(WASMGroupElement::from(self.session_public_key.0)),
            secret: WASMSessionSecretKey::from(WASMScalarNonZero::from(self.session_secret_key.0)),
        }
    }
    /// Update a session key share from one session to the other
    #[wasm_bindgen(js_name = updateSessionSecretKey)]
    pub fn wasm_update_session_secret_key(
        &mut self,
        old_key_share: WASMSessionKeyShare,
        new_key_share: WASMSessionKeyShare,
    ) {
        self.0
            .update_session_secret_key(old_key_share.0, new_key_share.0);
    }

    /// Decrypt an encrypted pseudonym.
    #[wasm_bindgen(js_name = decryptPseudonym)]
    pub fn wasm_decrypt_pseudonym(&self, encrypted: &WASMEncryptedPseudonym) -> WASMPseudonym {
        WASMPseudonym::from(self.decrypt(&encrypted.0))
    }
    /// Decrypt an encrypted data point.
    #[wasm_bindgen(js_name = decryptData)]
    pub fn wasm_decrypt_data(&self, encrypted: &WASMEncryptedDataPoint) -> WASMDataPoint {
        WASMDataPoint::from(self.decrypt(&encrypted.0))
    }
    /// Encrypt a data point with the session public key.
    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMDataPoint) -> WASMEncryptedDataPoint {
        let mut rng = rand::thread_rng();
        WASMEncryptedDataPoint::from(self.encrypt(&message.0, &mut rng))
    }

    /// Encrypt a pseudonym with the session public key.
    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        WASMEncryptedPseudonym(EncryptedPseudonym::from(
            self.encrypt(&message.0, &mut rng).value,
        ))
    }
}

/// An offline PEP client that can encrypt data, based on a global public key.
/// This client is used for encryption only, and does not have a session key pair.
/// This can be useful when encryption is done offline and no session key pair is available,
/// or when using a session key would leak information.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = OfflinePEPClient)]
pub struct WASMOfflinePEPClient(OfflinePEPClient);

#[wasm_bindgen(js_class = OfflinePEPClient)]
impl WASMOfflinePEPClient {
    /// Create a new offline PEP client from the given global public key.
    #[wasm_bindgen(constructor)]
    pub fn new(global_public_key: WASMGlobalPublicKey) -> Self {
        Self(OfflinePEPClient::new(GlobalPublicKey(*global_public_key.0)))
    }
    /// Encrypt a data point with the global public key.
    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMDataPoint) -> WASMEncryptedDataPoint {
        let mut rng = rand::thread_rng();
        WASMEncryptedDataPoint::from(self.encrypt(&message.0, &mut rng))
    }
    /// Encrypt a pseudonym with the global public key.
    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        WASMEncryptedPseudonym(EncryptedPseudonym::from(
            self.encrypt(&message.0, &mut rng).value,
        ))
    }
}
