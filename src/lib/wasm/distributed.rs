use crate::distributed::key_blinding::*;
use crate::distributed::systems::*;
use crate::high_level::contexts::*;
use crate::high_level::keys::*;
use crate::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
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

/// A blinded pseudonym global secret key, which is the pseudonym global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedPseudonymGlobalSecretKey)]
pub struct WASMBlindedPseudonymGlobalSecretKey(BlindedPseudonymGlobalSecretKey);

#[wasm_bindgen(js_class = "BlindedPseudonymGlobalSecretKey")]
impl WASMBlindedPseudonymGlobalSecretKey {
    /// Create a new [`WASMBlindedPseudonymGlobalSecretKey`] from a [`WASMScalarNonZero`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindedPseudonymGlobalSecretKey(BlindedPseudonymGlobalSecretKey(x.0))
    }

    /// Encode the [`WASMBlindedPseudonymGlobalSecretKey`] as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode a [`WASMBlindedPseudonymGlobalSecretKey`] from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::decode_from_slice(bytes.as_slice())
            .map(WASMBlindedPseudonymGlobalSecretKey)
    }
    /// Encode the [`WASMBlindedPseudonymGlobalSecretKey`] as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a [`WASMBlindedPseudonymGlobalSecretKey`] from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::decode_from_hex(hex)
            .map(WASMBlindedPseudonymGlobalSecretKey)
    }
}

/// A blinded attribute global secret key, which is the attribute global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedAttributeGlobalSecretKey)]
pub struct WASMBlindedAttributeGlobalSecretKey(BlindedAttributeGlobalSecretKey);

#[wasm_bindgen(js_class = "BlindedAttributeGlobalSecretKey")]
impl WASMBlindedAttributeGlobalSecretKey {
    /// Create a new [`WASMBlindedAttributeGlobalSecretKey`] from a [`WASMScalarNonZero`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindedAttributeGlobalSecretKey(BlindedAttributeGlobalSecretKey(x.0))
    }

    /// Encode the [`WASMBlindedAttributeGlobalSecretKey`] as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode a [`WASMBlindedAttributeGlobalSecretKey`] from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::decode_from_slice(bytes.as_slice())
            .map(WASMBlindedAttributeGlobalSecretKey)
    }
    /// Encode the [`WASMBlindedAttributeGlobalSecretKey`] as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a [`WASMBlindedAttributeGlobalSecretKey`] from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::decode_from_hex(hex)
            .map(WASMBlindedAttributeGlobalSecretKey)
    }
}

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`WASMBlindedPseudonymGlobalSecretKey`], a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymSessionKeyShare)]
pub struct WASMPseudonymSessionKeyShare(PseudonymSessionKeyShare);

#[wasm_bindgen(js_class = "PseudonymSessionKeyShare")]
impl WASMPseudonymSessionKeyShare {
    /// Create a new [`WASMPseudonymSessionKeyShare`] from a [`WASMScalarNonZero`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMPseudonymSessionKeyShare(PseudonymSessionKeyShare(x.0))
    }
    /// Encode the [`WASMPseudonymSessionKeyShare`] as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode a [`WASMPseudonymSessionKeyShare`] from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::decode_from_slice(bytes.as_slice())
            .map(WASMPseudonymSessionKeyShare)
    }
    /// Encode the [`WASMPseudonymSessionKeyShare`] as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a [`WASMPseudonymSessionKeyShare`] from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::decode_from_hex(hex).map(WASMPseudonymSessionKeyShare)
    }
}

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`WASMBlindedAttributeGlobalSecretKey`], an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeSessionKeyShare)]
pub struct WASMAttributeSessionKeyShare(AttributeSessionKeyShare);

#[wasm_bindgen(js_class = "AttributeSessionKeyShare")]
impl WASMAttributeSessionKeyShare {
    /// Create a new [`WASMAttributeSessionKeyShare`] from a [`WASMScalarNonZero`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMAttributeSessionKeyShare(AttributeSessionKeyShare(x.0))
    }
    /// Encode the [`WASMAttributeSessionKeyShare`] as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode a [`WASMAttributeSessionKeyShare`] from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMAttributeSessionKeyShare> {
        AttributeSessionKeyShare::decode_from_slice(bytes.as_slice())
            .map(WASMAttributeSessionKeyShare)
    }
    /// Encode the [`WASMAttributeSessionKeyShare`] as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a [`WASMAttributeSessionKeyShare`] from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMAttributeSessionKeyShare> {
        AttributeSessionKeyShare::decode_from_hex(hex).map(WASMAttributeSessionKeyShare)
    }
}

/// A pair of session key shares containing both pseudonym and attribute shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = SessionKeyShares)]
pub struct WASMSessionKeyShares(SessionKeyShares);

#[wasm_bindgen(js_class = "SessionKeyShares")]
impl WASMSessionKeyShares {
    /// Create a new [`WASMSessionKeyShares`] from pseudonym and attribute shares.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMPseudonymSessionKeyShare,
        attribute: WASMAttributeSessionKeyShare,
    ) -> Self {
        WASMSessionKeyShares(SessionKeyShares {
            pseudonym: pseudonym.0,
            attribute: attribute.0,
        })
    }

    /// Get the pseudonym session key share.
    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymSessionKeyShare {
        WASMPseudonymSessionKeyShare(self.0.pseudonym)
    }

    /// Get the attribute session key share.
    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeSessionKeyShare {
        WASMAttributeSessionKeyShare(self.0.attribute)
    }
}

/// A pair of blinded global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = BlindedGlobalKeys)]
pub struct WASMBlindedGlobalKeys(BlindedGlobalKeys);

#[wasm_bindgen(js_class = "BlindedGlobalKeys")]
impl WASMBlindedGlobalKeys {
    /// Create a new [`WASMBlindedGlobalKeys`] from pseudonym and attribute blinded keys.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMBlindedPseudonymGlobalSecretKey,
        attribute: WASMBlindedAttributeGlobalSecretKey,
    ) -> Self {
        WASMBlindedGlobalKeys(BlindedGlobalKeys {
            pseudonym: pseudonym.0,
            attribute: attribute.0,
        })
    }

    /// Get the blinded pseudonym global secret key.
    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMBlindedPseudonymGlobalSecretKey {
        WASMBlindedPseudonymGlobalSecretKey(self.0.pseudonym)
    }

    /// Get the blinded attribute global secret key.
    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMBlindedAttributeGlobalSecretKey {
        WASMBlindedAttributeGlobalSecretKey(self.0.attribute)
    }
}

/// Pseudonym session keys containing both public and secret keys.
#[derive(Copy, Clone, Debug, From, Into)]
#[wasm_bindgen(js_name = PseudonymSessionKeys)]
pub struct WASMPseudonymSessionKeys(PseudonymSessionKeys);

#[wasm_bindgen(js_class = "PseudonymSessionKeys")]
impl WASMPseudonymSessionKeys {
    /// Create new pseudonym session keys from public and secret keys.
    #[wasm_bindgen(constructor)]
    pub fn new(
        public: WASMPseudonymSessionPublicKey,
        secret: WASMPseudonymSessionSecretKey,
    ) -> Self {
        WASMPseudonymSessionKeys(PseudonymSessionKeys {
            public: PseudonymSessionPublicKey::from(public.0 .0),
            secret: PseudonymSessionSecretKey::from(secret.0 .0),
        })
    }

    /// Get the pseudonym session public key.
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMPseudonymSessionPublicKey {
        WASMPseudonymSessionPublicKey(WASMGroupElement::from(self.0.public.0))
    }

    /// Get the pseudonym session secret key.
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMPseudonymSessionSecretKey {
        WASMPseudonymSessionSecretKey(WASMScalarNonZero::from(self.0.secret.0))
    }
}

/// Attribute session keys containing both public and secret keys.
#[derive(Copy, Clone, Debug, From, Into)]
#[wasm_bindgen(js_name = AttributeSessionKeys)]
pub struct WASMAttributeSessionKeys(AttributeSessionKeys);

#[wasm_bindgen(js_class = "AttributeSessionKeys")]
impl WASMAttributeSessionKeys {
    /// Create new attribute session keys from public and secret keys.
    #[wasm_bindgen(constructor)]
    pub fn new(
        public: WASMAttributeSessionPublicKey,
        secret: WASMAttributeSessionSecretKey,
    ) -> Self {
        WASMAttributeSessionKeys(AttributeSessionKeys {
            public: AttributeSessionPublicKey::from(public.0 .0),
            secret: AttributeSessionSecretKey::from(secret.0 .0),
        })
    }

    /// Get the attribute session public key.
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMAttributeSessionPublicKey {
        WASMAttributeSessionPublicKey(WASMGroupElement::from(self.0.public.0))
    }

    /// Get the attribute session secret key.
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMAttributeSessionSecretKey {
        WASMAttributeSessionSecretKey(WASMScalarNonZero::from(self.0.secret.0))
    }
}

/// Session keys for both pseudonyms and attributes.
#[derive(Clone, From, Into)]
#[wasm_bindgen(js_name = SessionKeys)]
pub struct WASMSessionKeys(SessionKeys);

#[wasm_bindgen(js_class = "SessionKeys")]
impl WASMSessionKeys {
    /// Create new session keys from pseudonym and attribute keys.
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonym: WASMPseudonymSessionKeys, attribute: WASMAttributeSessionKeys) -> Self {
        WASMSessionKeys(SessionKeys {
            pseudonym: pseudonym.0,
            attribute: attribute.0,
        })
    }

    /// Get the pseudonym session keys.
    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymSessionKeys {
        WASMPseudonymSessionKeys(self.0.pseudonym)
    }

    /// Get the attribute session keys.
    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeSessionKeys {
        WASMAttributeSessionKeys(self.0.attribute)
    }
}

/// Create a [`WASMBlindedPseudonymGlobalSecretKey`] from a [`WASMPseudonymGlobalSecretKey`] and a list of [`WASMBlindingFactor`]s.
/// Used during system setup to blind the pseudonym global secret key.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
#[wasm_bindgen(js_name = makeBlindedPseudonymGlobalSecretKey)]
pub fn wasm_make_blinded_pseudonym_global_secret_key(
    global_secret_key: &WASMPseudonymGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> WASMBlindedPseudonymGlobalSecretKey {
    // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
    // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
    // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    WASMBlindedPseudonymGlobalSecretKey(
        make_blinded_pseudonym_global_secret_key(
            &PseudonymGlobalSecretKey::from(ScalarNonZero::from(global_secret_key.0)),
            &bs,
        )
        .unwrap(),
    )
}

/// Create a [`WASMBlindedAttributeGlobalSecretKey`] from a [`WASMAttributeGlobalSecretKey`] and a list of [`WASMBlindingFactor`]s.
/// Used during system setup to blind the attribute global secret key.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
#[wasm_bindgen(js_name = makeBlindedAttributeGlobalSecretKey)]
pub fn wasm_make_blinded_attribute_global_secret_key(
    global_secret_key: &WASMAttributeGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> WASMBlindedAttributeGlobalSecretKey {
    // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
    // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
    // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    WASMBlindedAttributeGlobalSecretKey(
        make_blinded_attribute_global_secret_key(
            &AttributeGlobalSecretKey::from(ScalarNonZero::from(global_secret_key.0)),
            &bs,
        )
        .unwrap(),
    )
}

/// Create [`WASMBlindedGlobalKeys`] (both pseudonym and attribute) from global secret keys and blinding factors.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1 for either key type.
#[wasm_bindgen(js_name = makeBlindedGlobalKeys)]
pub fn wasm_make_blinded_global_keys(
    pseudonym_global_secret_key: &WASMPseudonymGlobalSecretKey,
    attribute_global_secret_key: &WASMAttributeGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> WASMBlindedGlobalKeys {
    // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_global_keys(
        &PseudonymGlobalSecretKey::from(ScalarNonZero::from(pseudonym_global_secret_key.0)),
        &AttributeGlobalSecretKey::from(ScalarNonZero::from(attribute_global_secret_key.0)),
        &bs,
    )
    .unwrap();
    WASMBlindedGlobalKeys(BlindedGlobalKeys {
        pseudonym: result.pseudonym,
        attribute: result.attribute,
    })
}

/// Setup a distributed system with both pseudonym and attribute global keys, blinded global secret keys,
/// and a list of blinding factors.
/// The blinding factors should securely be transferred to the transcryptors, the global public keys
/// and blinded global secret keys can be publicly shared with anyone and are required by clients.
///
/// Returns [pseudonymPublicKey, attributePublicKey, blindedGlobalKeys, blindingFactors[]]
#[wasm_bindgen(js_name = makeDistributedGlobalKeys)]
pub fn wasm_make_distributed_global_keys(n: usize) -> Box<[JsValue]> {
    let mut rng = rand::thread_rng();
    let (pseudonym_pk, attribute_pk, blinded_keys, blinding_factors) =
        make_distributed_global_keys(n, &mut rng);

    let pseudonym_key = WASMPseudonymGlobalPublicKey(WASMGroupElement(pseudonym_pk.0));
    let attribute_key = WASMAttributeGlobalPublicKey(WASMGroupElement(attribute_pk.0));
    let blinded = WASMBlindedGlobalKeys(blinded_keys);
    let factors: Vec<WASMBlindingFactor> = blinding_factors
        .into_iter()
        .map(WASMBlindingFactor)
        .collect();

    vec![
        JsValue::from(pseudonym_key),
        JsValue::from(attribute_key),
        JsValue::from(blinded),
        JsValue::from(
            factors
                .into_iter()
                .map(JsValue::from)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
    ]
    .into_boxed_slice()
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
    /// Generate a pseudonym session key share for the given session.
    #[wasm_bindgen(js_name = pseudonymSessionKeyShare)]
    pub fn wasm_pseudonym_session_key_share(&self, session: &str) -> WASMPseudonymSessionKeyShare {
        WASMPseudonymSessionKeyShare(
            self.pseudonym_session_key_share(&EncryptionContext::from(session)),
        )
    }
    /// Generate an attribute session key share for the given session.
    #[wasm_bindgen(js_name = attributeSessionKeyShare)]
    pub fn wasm_attribute_session_key_share(&self, session: &str) -> WASMAttributeSessionKeyShare {
        WASMAttributeSessionKeyShare(
            self.attribute_session_key_share(&EncryptionContext::from(session)),
        )
    }
    /// Generate both pseudonym and attribute session key shares for the given session.
    /// This is a convenience method that returns both shares together.
    #[wasm_bindgen(js_name = sessionKeyShares)]
    pub fn wasm_session_key_shares(&self, session: &str) -> WASMSessionKeyShares {
        WASMSessionKeyShares(self.session_key_shares(&EncryptionContext::from(session)))
    }
    /// Generate attribute rekey info to rekey from a given session to another.
    #[wasm_bindgen(js_name = attributeRekeyInfo)]
    pub fn wasm_attribute_rekey_info(
        &self,
        session_from: &str,
        session_to: &str,
    ) -> WASMAttributeRekeyInfo {
        WASMAttributeRekeyInfo::from(self.attribute_rekey_info(
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

    /// Rekey an [`WASMEncryptedAttribute`] from one session to another, using [`WASMAttributeRekeyInfo`].
    #[wasm_bindgen(js_name = rekey)]
    pub fn wasm_rekey(
        &self,
        encrypted: &WASMEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> WASMEncryptedAttribute {
        WASMEncryptedAttribute::from(
            self.rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)),
        )
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
/// A PEP client that can encrypt and decrypt data, based on separate session key pairs for pseudonyms and attributes.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PEPClient)]
pub struct WASMPEPClient(PEPClient);
#[wasm_bindgen(js_class = PEPClient)]
impl WASMPEPClient {
    /// Create a new PEP client from blinded global keys and session key shares.
    #[wasm_bindgen(constructor)]
    pub fn new(
        blinded_global_keys: &WASMBlindedGlobalKeys,
        session_key_shares: Vec<WASMSessionKeyShares>,
    ) -> Self {
        // FIXME we do not pass a reference to the session key shares vector, since WASM does not support references to arrays of structs
        // As a result, we have to clone the session key shares BEFORE passing them to the function, so in javascript.
        // Simply by passing the session key shares to this function will turn them into null pointers, so we cannot use them anymore in javascript.
        let shares: Vec<SessionKeyShares> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShares {
                pseudonym: PseudonymSessionKeyShare(x.0.pseudonym.0),
                attribute: AttributeSessionKeyShare(x.0.attribute.0),
            })
            .collect();
        let blinded_keys = BlindedGlobalKeys {
            pseudonym: blinded_global_keys.0.pseudonym,
            attribute: blinded_global_keys.0.attribute,
        };
        Self(PEPClient::new(blinded_keys, &shares))
    }

    /// Create a new PEP client from separate blinded global keys and session key shares.
    /// This is a convenience method for when you have separate keys instead of combined types.
    #[wasm_bindgen(js_name = fromSeparateKeys)]
    pub fn from_separate_keys(
        blinded_global_pseudonym_key: &WASMBlindedPseudonymGlobalSecretKey,
        pseudonym_session_key_shares: Vec<WASMPseudonymSessionKeyShare>,
        blinded_global_attribute_key: &WASMBlindedAttributeGlobalSecretKey,
        attribute_session_key_shares: Vec<WASMAttributeSessionKeyShare>,
    ) -> Self {
        // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
        // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
        // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
        let pseudonym_shares: Vec<PseudonymSessionKeyShare> = pseudonym_session_key_shares
            .into_iter()
            .map(|x| PseudonymSessionKeyShare(x.0 .0))
            .collect();
        let attribute_shares: Vec<AttributeSessionKeyShare> = attribute_session_key_shares
            .into_iter()
            .map(|x| AttributeSessionKeyShare(x.0 .0))
            .collect();

        let shares: Vec<SessionKeyShares> = pseudonym_shares
            .iter()
            .zip(attribute_shares.iter())
            .map(|(p, a)| SessionKeyShares {
                pseudonym: *p,
                attribute: *a,
            })
            .collect();

        let blinded_keys = BlindedGlobalKeys {
            pseudonym: blinded_global_pseudonym_key.0,
            attribute: blinded_global_attribute_key.0,
        };

        Self(PEPClient::new(blinded_keys, &shares))
    }

    /// Create a new PEP client from combined session key shares.
    /// This is a convenience method for compatibility that accepts separate blinded keys and combined shares.
    #[wasm_bindgen(js_name = fromSessionKeyShares)]
    pub fn from_session_key_shares(
        blinded_global_pseudonym_key: &WASMBlindedPseudonymGlobalSecretKey,
        blinded_global_attribute_key: &WASMBlindedAttributeGlobalSecretKey,
        session_key_shares: Vec<WASMSessionKeyShares>,
    ) -> Self {
        let blinded_keys = WASMBlindedGlobalKeys(BlindedGlobalKeys {
            pseudonym: blinded_global_pseudonym_key.0,
            attribute: blinded_global_attribute_key.0,
        });
        Self::new(&blinded_keys, session_key_shares)
    }

    /// Restore a PEP client from the given session keys.
    #[wasm_bindgen(js_name = restore)]
    pub fn wasm_restore(
        pseudonym_session_keys: &WASMPseudonymSessionKeyPair,
        attribute_session_keys: &WASMAttributeSessionKeyPair,
    ) -> Self {
        let keys = SessionKeys {
            pseudonym: PseudonymSessionKeys {
                public: PseudonymSessionPublicKey(**pseudonym_session_keys.public),
                secret: PseudonymSessionSecretKey(**pseudonym_session_keys.secret),
            },
            attribute: AttributeSessionKeys {
                public: AttributeSessionPublicKey(**attribute_session_keys.public),
                secret: AttributeSessionSecretKey(**attribute_session_keys.secret),
            },
        };
        Self(PEPClient::restore(keys))
    }

    /// Dump the pseudonym session key pair.
    #[wasm_bindgen(js_name = dumpPseudonymKeys)]
    pub fn wasm_dump_pseudonym_keys(&self) -> WASMPseudonymSessionKeyPair {
        let keys = self.0.dump();
        WASMPseudonymSessionKeyPair {
            public: WASMPseudonymSessionPublicKey::from(WASMGroupElement::from(
                keys.pseudonym.public.0,
            )),
            secret: WASMPseudonymSessionSecretKey::from(WASMScalarNonZero::from(
                keys.pseudonym.secret.0,
            )),
        }
    }

    /// Dump the attribute session key pair.
    #[wasm_bindgen(js_name = dumpAttributeKeys)]
    pub fn wasm_dump_attribute_keys(&self) -> WASMAttributeSessionKeyPair {
        let keys = self.0.dump();
        WASMAttributeSessionKeyPair {
            public: WASMAttributeSessionPublicKey::from(WASMGroupElement::from(
                keys.attribute.public.0,
            )),
            secret: WASMAttributeSessionSecretKey::from(WASMScalarNonZero::from(
                keys.attribute.secret.0,
            )),
        }
    }

    /// Update a pseudonym session key share from one session to the other
    #[wasm_bindgen(js_name = updatePseudonymSessionSecretKey)]
    pub fn wasm_update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: WASMPseudonymSessionKeyShare,
        new_key_share: WASMPseudonymSessionKeyShare,
    ) {
        self.0
            .update_pseudonym_session_secret_key(old_key_share.0, new_key_share.0);
    }

    /// Update an attribute session key share from one session to the other
    #[wasm_bindgen(js_name = updateAttributeSessionSecretKey)]
    pub fn wasm_update_attribute_session_secret_key(
        &mut self,
        old_key_share: WASMAttributeSessionKeyShare,
        new_key_share: WASMAttributeSessionKeyShare,
    ) {
        self.0
            .update_attribute_session_secret_key(old_key_share.0, new_key_share.0);
    }

    /// Update both pseudonym and attribute session key shares from one session to another.
    /// This is a convenience method that updates both shares together.
    #[wasm_bindgen(js_name = updateSessionSecretKeys)]
    pub fn wasm_update_session_secret_keys(
        &mut self,
        old_key_shares: WASMSessionKeyShares,
        new_key_shares: WASMSessionKeyShares,
    ) {
        self.0
            .update_session_secret_keys(old_key_shares.0, new_key_shares.0);
    }

    /// Decrypt an encrypted pseudonym.
    #[wasm_bindgen(js_name = decryptPseudonym)]
    pub fn wasm_decrypt_pseudonym(&self, encrypted: &WASMEncryptedPseudonym) -> WASMPseudonym {
        WASMPseudonym::from(self.decrypt_pseudonym(&encrypted.0))
    }
    /// Decrypt an encrypted attribute.
    #[wasm_bindgen(js_name = decryptData)]
    pub fn wasm_decrypt_data(&self, encrypted: &WASMEncryptedAttribute) -> WASMAttribute {
        WASMAttribute::from(self.decrypt_attribute(&encrypted.0))
    }
    /// Encrypt an attribute with the session public key.
    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMAttribute) -> WASMEncryptedAttribute {
        let mut rng = rand::thread_rng();
        WASMEncryptedAttribute::from(self.encrypt_attribute(&message.0, &mut rng))
    }

    /// Encrypt a pseudonym with the session public key.
    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        WASMEncryptedPseudonym(self.encrypt_pseudonym(&message.0, &mut rng))
    }
}

/// An offline PEP client that can encrypt data, based on global public keys for pseudonyms and attributes.
/// This client is used for encryption only, and does not have session key pairs.
/// This can be useful when encryption is done offline and no session key pairs are available,
/// or when using a session key would leak information.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = OfflinePEPClient)]
pub struct WASMOfflinePEPClient(OfflinePEPClient);

#[wasm_bindgen(js_class = OfflinePEPClient)]
impl WASMOfflinePEPClient {
    /// Create a new offline PEP client from the given global public keys.
    #[wasm_bindgen(constructor)]
    pub fn new(
        global_pseudonym_public_key: WASMPseudonymGlobalPublicKey,
        global_attribute_public_key: WASMAttributeGlobalPublicKey,
    ) -> Self {
        Self(OfflinePEPClient::new(
            PseudonymGlobalPublicKey(*global_pseudonym_public_key.0),
            AttributeGlobalPublicKey(*global_attribute_public_key.0),
        ))
    }
    /// Encrypt an attribute with the global public key.
    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMAttribute) -> WASMEncryptedAttribute {
        let mut rng = rand::thread_rng();
        WASMEncryptedAttribute::from(self.encrypt_attribute(&message.0, &mut rng))
    }
    /// Encrypt a pseudonym with the global public key.
    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        WASMEncryptedPseudonym(self.encrypt_pseudonym(&message.0, &mut rng))
    }
}
