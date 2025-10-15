use crate::distributed::key_blinding::*;
use crate::distributed::systems::*;
use crate::high_level::contexts::*;
use crate::high_level::data_types::{EncryptedAttribute, EncryptedPseudonym};
use crate::high_level::keys::*;
use crate::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
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

/// Global public keys for both pseudonyms and attributes.
#[derive(Clone, Copy, From)]
#[wasm_bindgen(js_name = GlobalPublicKeys)]
pub struct WASMGlobalPublicKeys {
    pseudonym: WASMPseudonymGlobalPublicKey,
    attribute: WASMAttributeGlobalPublicKey,
}

#[wasm_bindgen(js_class = "GlobalPublicKeys")]
impl WASMGlobalPublicKeys {
    /// Create new global public keys from pseudonym and attribute public keys.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMPseudonymGlobalPublicKey,
        attribute: WASMAttributeGlobalPublicKey,
    ) -> Self {
        WASMGlobalPublicKeys {
            pseudonym,
            attribute,
        }
    }

    /// Get the pseudonym global public key.
    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymGlobalPublicKey {
        self.pseudonym
    }

    /// Get the attribute global public key.
    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeGlobalPublicKey {
        self.attribute
    }
}

/// Create [`WASMBlindedGlobalKeys`] (both pseudonym and attribute) from global secret keys and blinding factors.
/// Returns `undefined` if the product of all blinding factors accidentally turns out to be 1 for either key type.
#[wasm_bindgen(js_name = makeBlindedGlobalKeys)]
pub fn wasm_make_blinded_global_keys(
    pseudonym_global_secret_key: &WASMPseudonymGlobalSecretKey,
    attribute_global_secret_key: &WASMAttributeGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> Option<WASMBlindedGlobalKeys> {
    // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    make_blinded_global_keys(
        &PseudonymGlobalSecretKey::from(pseudonym_global_secret_key.0 .0),
        &AttributeGlobalSecretKey::from(attribute_global_secret_key.0 .0),
        &bs,
    )
    .map(WASMBlindedGlobalKeys)
}

/// Setup a distributed system with both pseudonym and attribute global keys, blinded global secret keys,
/// and a list of blinding factors.
/// The blinding factors should securely be transferred to the transcryptors, the global public keys
/// and blinded global secret keys can be publicly shared with anyone and are required by clients.
///
/// Returns [globalPublicKeys, blindedGlobalKeys, blindingFactors[]]
#[wasm_bindgen(js_name = makeDistributedGlobalKeys)]
pub fn wasm_make_distributed_global_keys(n: usize) -> Box<[JsValue]> {
    let mut rng = rand::thread_rng();
    let (global_public_keys, blinded_keys, blinding_factors) =
        make_distributed_global_keys(n, &mut rng);

    let global_keys = WASMGlobalPublicKeys {
        pseudonym: WASMPseudonymGlobalPublicKey(WASMGroupElement(global_public_keys.pseudonym.0)),
        attribute: WASMAttributeGlobalPublicKey(WASMGroupElement(global_public_keys.attribute.0)),
    };
    let blinded = WASMBlindedGlobalKeys(blinded_keys);
    let factors: Vec<WASMBlindingFactor> = blinding_factors
        .into_iter()
        .map(WASMBlindingFactor)
        .collect();

    vec![
        JsValue::from(global_keys),
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

/// Creates a blinded pseudonym global secret key from an unblinded key and blinding factors.
///
/// Returns `undefined` if the product of the blinding factors is 1 (which would make the blinding ineffective).
#[wasm_bindgen(js_name = makeBlindedPseudonymGlobalSecretKey)]
pub fn wasm_make_blinded_pseudonym_global_secret_key(
    global_secret_key: &WASMPseudonymGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> Option<WASMBlindedPseudonymGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    make_blinded_pseudonym_global_secret_key(
        &PseudonymGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .map(WASMBlindedPseudonymGlobalSecretKey)
}

/// Creates a blinded attribute global secret key from an unblinded key and blinding factors.
///
/// Returns `undefined` if the product of the blinding factors is 1 (which would make the blinding ineffective).
#[wasm_bindgen(js_name = makeBlindedAttributeGlobalSecretKey)]
pub fn wasm_make_blinded_attribute_global_secret_key(
    global_secret_key: &WASMAttributeGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> Option<WASMBlindedAttributeGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    make_blinded_attribute_global_secret_key(
        &AttributeGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .map(WASMBlindedAttributeGlobalSecretKey)
}

/// Creates a pseudonym session key share from a rekey factor and blinding factor.
#[wasm_bindgen(js_name = makePseudonymSessionKeyShare)]
pub fn wasm_make_pseudonym_session_key_share(
    rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMPseudonymSessionKeyShare {
    WASMPseudonymSessionKeyShare(make_pseudonym_session_key_share(
        &rekey_factor.0,
        &blinding_factor.0,
    ))
}

/// Creates an attribute session key share from a rekey factor and blinding factor.
#[wasm_bindgen(js_name = makeAttributeSessionKeyShare)]
pub fn wasm_make_attribute_session_key_share(
    rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMAttributeSessionKeyShare {
    WASMAttributeSessionKeyShare(make_attribute_session_key_share(
        &rekey_factor.0,
        &blinding_factor.0,
    ))
}

/// Creates both pseudonym and attribute session key shares from rekey factors and a blinding factor.
#[wasm_bindgen(js_name = makeSessionKeyShares)]
pub fn wasm_make_session_key_shares(
    pseudonym_rekey_factor: &WASMScalarNonZero,
    attribute_rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMSessionKeyShares {
    WASMSessionKeyShares(make_session_key_shares(
        &pseudonym_rekey_factor.0,
        &attribute_rekey_factor.0,
        &blinding_factor.0,
    ))
}

/// Combines multiple pseudonym session key shares into a single pseudonym session key pair.
#[wasm_bindgen(js_name = makePseudonymSessionKey)]
pub fn wasm_make_pseudonym_session_key(
    blinded_global_key: WASMBlindedPseudonymGlobalSecretKey,
    shares: Vec<WASMPseudonymSessionKeyShare>,
) -> WASMPseudonymSessionKeyPair {
    let shares: Vec<PseudonymSessionKeyShare> = shares.into_iter().map(|s| s.0).collect();
    let (public, secret) = make_pseudonym_session_key(blinded_global_key.0, &shares);
    WASMPseudonymSessionKeyPair {
        public: WASMPseudonymSessionPublicKey(WASMGroupElement(public.0)),
        secret: WASMPseudonymSessionSecretKey(WASMScalarNonZero(secret.0)),
    }
}

/// Combines multiple attribute session key shares into a single attribute session key pair.
#[wasm_bindgen(js_name = makeAttributeSessionKey)]
pub fn wasm_make_attribute_session_key(
    blinded_global_key: WASMBlindedAttributeGlobalSecretKey,
    shares: Vec<WASMAttributeSessionKeyShare>,
) -> WASMAttributeSessionKeyPair {
    let shares: Vec<AttributeSessionKeyShare> = shares.into_iter().map(|s| s.0).collect();
    let (public, secret) = make_attribute_session_key(blinded_global_key.0, &shares);
    WASMAttributeSessionKeyPair {
        public: WASMAttributeSessionPublicKey(WASMGroupElement(public.0)),
        secret: WASMAttributeSessionSecretKey(WASMScalarNonZero(secret.0)),
    }
}

/// Combines multiple session key shares (both pseudonym and attribute) into full session keys.
#[wasm_bindgen(js_name = makeSessionKeysDistributed)]
pub fn wasm_make_session_keys_distributed(
    blinded_global_keys: WASMBlindedGlobalKeys,
    shares: Vec<WASMSessionKeyShares>,
) -> WASMSessionKeys {
    let shares: Vec<SessionKeyShares> = shares.into_iter().map(|s| s.0).collect();
    WASMSessionKeys(make_session_keys_distributed(
        blinded_global_keys.0,
        &shares,
    ))
}

/// Updates a pseudonym session key by removing an old share and adding a new share.
#[wasm_bindgen(js_name = updatePseudonymSessionKey)]
pub fn wasm_update_pseudonym_session_key(
    session_secret_key: &WASMPseudonymSessionSecretKey,
    old_share: &WASMPseudonymSessionKeyShare,
    new_share: &WASMPseudonymSessionKeyShare,
) -> WASMPseudonymSessionKeyPair {
    let (public, secret) =
        update_pseudonym_session_key(session_secret_key.0 .0.into(), old_share.0, new_share.0);
    WASMPseudonymSessionKeyPair {
        public: WASMPseudonymSessionPublicKey(WASMGroupElement(public.0)),
        secret: WASMPseudonymSessionSecretKey(WASMScalarNonZero(secret.0)),
    }
}

/// Updates an attribute session key by removing an old share and adding a new share.
#[wasm_bindgen(js_name = updateAttributeSessionKey)]
pub fn wasm_update_attribute_session_key(
    session_secret_key: &WASMAttributeSessionSecretKey,
    old_share: &WASMAttributeSessionKeyShare,
    new_share: &WASMAttributeSessionKeyShare,
) -> WASMAttributeSessionKeyPair {
    let (public, secret) =
        update_attribute_session_key(session_secret_key.0 .0.into(), old_share.0, new_share.0);
    WASMAttributeSessionKeyPair {
        public: WASMAttributeSessionPublicKey(WASMGroupElement(public.0)),
        secret: WASMAttributeSessionSecretKey(WASMScalarNonZero(secret.0)),
    }
}

/// Updates session keys by removing old shares and adding new shares.
#[wasm_bindgen(js_name = updateSessionKeys)]
pub fn wasm_update_session_keys(
    session_keys: WASMSessionKeys,
    old_shares: WASMSessionKeyShares,
    new_shares: WASMSessionKeyShares,
) -> WASMSessionKeys {
    WASMSessionKeys(update_session_keys(
        session_keys.0,
        old_shares.0,
        new_shares.0,
    ))
}

/// Generates distributed pseudonym global keys with blinding.
///
/// Returns `[globalPublicKey, blindedGlobalSecretKey, blindingFactors]`.
#[wasm_bindgen(js_name = makeDistributedPseudonymGlobalKeys)]
pub fn wasm_make_distributed_pseudonym_global_keys(n: usize) -> Box<[JsValue]> {
    let mut rng = rand::thread_rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_pseudonym_global_keys(n, &mut rng);

    let public = WASMPseudonymGlobalPublicKey(WASMGroupElement(public_key.0));
    let blinded = WASMBlindedPseudonymGlobalSecretKey(blinded_key);
    let factors: Vec<WASMBlindingFactor> = blinding_factors
        .into_iter()
        .map(WASMBlindingFactor)
        .collect();

    vec![
        JsValue::from(public),
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

/// Generates distributed attribute global keys with blinding.
///
/// Returns `[globalPublicKey, blindedGlobalSecretKey, blindingFactors]`.
#[wasm_bindgen(js_name = makeDistributedAttributeGlobalKeys)]
pub fn wasm_make_distributed_attribute_global_keys(n: usize) -> Box<[JsValue]> {
    let mut rng = rand::thread_rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_attribute_global_keys(n, &mut rng);

    let public = WASMAttributeGlobalPublicKey(WASMGroupElement(public_key.0));
    let blinded = WASMBlindedAttributeGlobalSecretKey(blinded_key);
    let factors: Vec<WASMBlindingFactor> = blinding_factors
        .into_iter()
        .map(WASMBlindingFactor)
        .collect();

    vec![
        JsValue::from(public),
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
        session_from: Option<String>,
        session_to: Option<String>,
    ) -> WASMAttributeRekeyInfo {
        WASMAttributeRekeyInfo::from(
            self.attribute_rekey_info(
                session_from
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
                session_to
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
            ),
        )
    }

    /// Generate a pseudonym rekey info to rekey pseudonyms from a given session to another.
    #[wasm_bindgen(js_name = pseudonymRekeyInfo)]
    pub fn wasm_pseudonym_rekey_info(
        &self,
        session_from: Option<String>,
        session_to: Option<String>,
    ) -> WASMPseudonymRekeyFactor {
        WASMPseudonymRekeyFactor::from(
            self.pseudonym_rekey_info(
                session_from
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
                session_to
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
            ),
        )
    }

    /// Generate a pseudonymization info to pseudonymize from a given pseudonymization domain
    /// and session to another.
    #[wasm_bindgen(js_name = pseudonymizationInfo)]
    pub fn wasm_pseudonymization_info(
        &self,
        domain_from: &str,
        domain_to: &str,
        session_from: Option<String>,
        session_to: Option<String>,
    ) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo::from(
            self.pseudonymization_info(
                &PseudonymizationDomain::from(domain_from),
                &PseudonymizationDomain::from(domain_to),
                session_from
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
                session_to
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
            ),
        )
    }

    /// Generate transcryption info to transcrypt from a given pseudonymization domain and session to another.
    #[wasm_bindgen(js_name = transcryptionInfo)]
    pub fn wasm_transcryption_info(
        &self,
        domain_from: &str,
        domain_to: &str,
        session_from: Option<String>,
        session_to: Option<String>,
    ) -> WASMTranscryptionInfo {
        WASMTranscryptionInfo::from(
            self.transcryption_info(
                &PseudonymizationDomain::from(domain_from),
                &PseudonymizationDomain::from(domain_to),
                session_from
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
                session_to
                    .as_ref()
                    .map(|s| EncryptionContext::from(s.as_str()))
                    .as_ref(),
            ),
        )
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

    /// Rekey a batch of [`WASMEncryptedAttribute`]s from one session to another, using [`WASMAttributeRekeyInfo`].
    #[wasm_bindgen(js_name = rekeyBatch)]
    pub fn wasm_rekey_batch(
        &self,
        encrypted: Vec<WASMEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Vec<WASMEncryptedAttribute> {
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
            .map(WASMEncryptedAttribute::from)
            .collect()
    }

    /// Pseudonymize a batch of [`WASMEncryptedPseudonym`]s from one pseudonymization domain and
    /// session to another, using [`WASMPseudonymizationInfo`].
    #[wasm_bindgen(js_name = pseudonymizeBatch)]
    pub fn wasm_pseudonymize_batch(
        &self,
        encrypted: Vec<WASMEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> Vec<WASMEncryptedPseudonym> {
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
            .map(WASMEncryptedPseudonym::from)
            .collect()
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

    /// Restore a PEP client from the given session keys.
    #[wasm_bindgen(js_name = restore)]
    pub fn wasm_restore(keys: &WASMSessionKeys) -> Self {
        Self(PEPClient::restore(keys.clone().into()))
    }

    /// Dump the session keys.
    #[wasm_bindgen(js_name = dump)]
    pub fn wasm_dump(&self) -> WASMSessionKeys {
        WASMSessionKeys(*self.dump())
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
    pub fn new(global_keys: &WASMGlobalPublicKeys) -> Self {
        let global_keys = GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey(*global_keys.pseudonym.0),
            attribute: AttributeGlobalPublicKey(*global_keys.attribute.0),
        };
        Self(OfflinePEPClient::new(global_keys))
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
