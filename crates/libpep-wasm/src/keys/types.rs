use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::keys::types::*;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A pseudonym session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymSessionSecretKey)]
pub struct WASMPseudonymSessionSecretKey(pub WASMScalarNonZero);

/// An attribute session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeSessionSecretKey)]
pub struct WASMAttributeSessionSecretKey(pub WASMScalarNonZero);

/// A pseudonym global secret key from which pseudonym session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymGlobalSecretKey)]
pub struct WASMPseudonymGlobalSecretKey(pub WASMScalarNonZero);

/// An attribute global secret key from which attribute session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = AttributeGlobalSecretKey)]
pub struct WASMAttributeGlobalSecretKey(pub WASMScalarNonZero);

/// A pseudonym session public key used to encrypt pseudonyms against.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymSessionPublicKey)]
pub struct WASMPseudonymSessionPublicKey(pub WASMGroupElement);

/// An attribute session public key used to encrypt attributes against.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeSessionPublicKey)]
pub struct WASMAttributeSessionPublicKey(pub WASMGroupElement);

/// A pseudonym global public key from which pseudonym session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymGlobalPublicKey)]
pub struct WASMPseudonymGlobalPublicKey(pub WASMGroupElement);

#[wasm_bindgen(js_class = "PseudonymGlobalPublicKey")]
impl WASMPseudonymGlobalPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        Self(x)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0 .0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        use crate::arithmetic::group_elements::GroupElement;
        GroupElement::from_slice(&bytes).map(|x| Self(x.into()))
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        use crate::arithmetic::group_elements::GroupElement;
        GroupElement::from_hex(hex).map(|x| Self(x.into()))
    }
}

/// An attribute global public key from which attribute session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = AttributeGlobalPublicKey)]
pub struct WASMAttributeGlobalPublicKey(pub WASMGroupElement);

#[wasm_bindgen(js_class = "AttributeGlobalPublicKey")]
impl WASMAttributeGlobalPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        Self(x)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0 .0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        use crate::arithmetic::group_elements::GroupElement;
        GroupElement::from_slice(&bytes).map(|x| Self(x.into()))
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        use crate::arithmetic::group_elements::GroupElement;
        GroupElement::from_hex(hex).map(|x| Self(x.into()))
    }
}

/// Pseudonym session key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymSessionKeyPair)]
pub struct WASMPseudonymSessionKeyPair {
    public: WASMPseudonymSessionPublicKey,
    secret: WASMPseudonymSessionSecretKey,
}

#[wasm_bindgen(js_class = "PseudonymSessionKeyPair")]
impl WASMPseudonymSessionKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMPseudonymSessionPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMPseudonymSessionSecretKey {
        self.secret
    }
}

impl WASMPseudonymSessionKeyPair {
    pub fn new(
        public: WASMPseudonymSessionPublicKey,
        secret: WASMPseudonymSessionSecretKey,
    ) -> Self {
        Self { public, secret }
    }
}

/// Attribute session key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = AttributeSessionKeyPair)]
pub struct WASMAttributeSessionKeyPair {
    public: WASMAttributeSessionPublicKey,
    secret: WASMAttributeSessionSecretKey,
}

#[wasm_bindgen(js_class = "AttributeSessionKeyPair")]
impl WASMAttributeSessionKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMAttributeSessionPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMAttributeSessionSecretKey {
        self.secret
    }
}

impl WASMAttributeSessionKeyPair {
    pub fn new(
        public: WASMAttributeSessionPublicKey,
        secret: WASMAttributeSessionSecretKey,
    ) -> Self {
        Self { public, secret }
    }
}

/// Pseudonym global key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymGlobalKeyPair)]
pub struct WASMPseudonymGlobalKeyPair {
    public: WASMPseudonymGlobalPublicKey,
    secret: WASMPseudonymGlobalSecretKey,
}

#[wasm_bindgen(js_class = "PseudonymGlobalKeyPair")]
impl WASMPseudonymGlobalKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(public: WASMPseudonymGlobalPublicKey, secret: WASMPseudonymGlobalSecretKey) -> Self {
        Self { public, secret }
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMPseudonymGlobalPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMPseudonymGlobalSecretKey {
        self.secret
    }
}

/// Attribute global key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = AttributeGlobalKeyPair)]
pub struct WASMAttributeGlobalKeyPair {
    public: WASMAttributeGlobalPublicKey,
    secret: WASMAttributeGlobalSecretKey,
}

#[wasm_bindgen(js_class = "AttributeGlobalKeyPair")]
impl WASMAttributeGlobalKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(public: WASMAttributeGlobalPublicKey, secret: WASMAttributeGlobalSecretKey) -> Self {
        Self { public, secret }
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMAttributeGlobalPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMAttributeGlobalSecretKey {
        self.secret
    }
}

/// Combined global public keys for both pseudonyms and attributes.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalPublicKeys)]
pub struct WASMGlobalPublicKeys {
    pseudonym: WASMPseudonymGlobalPublicKey,
    attribute: WASMAttributeGlobalPublicKey,
}

#[wasm_bindgen(js_class = "GlobalPublicKeys")]
impl WASMGlobalPublicKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMPseudonymGlobalPublicKey,
        attribute: WASMAttributeGlobalPublicKey,
    ) -> Self {
        Self {
            pseudonym,
            attribute,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymGlobalPublicKey {
        self.pseudonym
    }

    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeGlobalPublicKey {
        self.attribute
    }
}

/// Combined global secret keys for both pseudonyms and attributes.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalSecretKeys)]
pub struct WASMGlobalSecretKeys {
    pseudonym: WASMPseudonymGlobalSecretKey,
    attribute: WASMAttributeGlobalSecretKey,
}

#[wasm_bindgen(js_class = "GlobalSecretKeys")]
impl WASMGlobalSecretKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMPseudonymGlobalSecretKey,
        attribute: WASMAttributeGlobalSecretKey,
    ) -> Self {
        Self {
            pseudonym,
            attribute,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymGlobalSecretKey {
        self.pseudonym
    }

    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeGlobalSecretKey {
        self.attribute
    }
}

/// Combined global key pairs for both pseudonyms and attributes.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalKeyPairs)]
pub struct WASMGlobalKeyPairs {
    public: WASMGlobalPublicKeys,
    secret: WASMGlobalSecretKeys,
}

#[wasm_bindgen(js_class = "GlobalKeyPairs")]
impl WASMGlobalKeyPairs {
    #[wasm_bindgen(constructor)]
    pub fn new(public: WASMGlobalPublicKeys, secret: WASMGlobalSecretKeys) -> Self {
        Self { public, secret }
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMGlobalPublicKeys {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMGlobalSecretKeys {
        self.secret
    }
}

/// Session keys for encrypting and decrypting data.
/// Pseudonym session keys containing both public and secret keys.
#[wasm_bindgen(js_name = PseudonymSessionKeys)]
#[derive(Clone, Copy)]
pub struct WASMPseudonymSessionKeys {
    public: WASMPseudonymSessionPublicKey,
    secret: WASMPseudonymSessionSecretKey,
}

#[wasm_bindgen(js_class = "PseudonymSessionKeys")]
impl WASMPseudonymSessionKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        public: WASMPseudonymSessionPublicKey,
        secret: WASMPseudonymSessionSecretKey,
    ) -> Self {
        Self { public, secret }
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMPseudonymSessionPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMPseudonymSessionSecretKey {
        self.secret
    }
}

/// Attribute session keys containing both public and secret keys.
#[wasm_bindgen(js_name = AttributeSessionKeys)]
#[derive(Clone, Copy)]
pub struct WASMAttributeSessionKeys {
    public: WASMAttributeSessionPublicKey,
    secret: WASMAttributeSessionSecretKey,
}

#[wasm_bindgen(js_class = "AttributeSessionKeys")]
impl WASMAttributeSessionKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        public: WASMAttributeSessionPublicKey,
        secret: WASMAttributeSessionSecretKey,
    ) -> Self {
        Self { public, secret }
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMAttributeSessionPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMAttributeSessionSecretKey {
        self.secret
    }
}

/// Session keys for both pseudonyms and attributes.
/// Contains both pseudonym and attribute session keys (public and secret).
#[wasm_bindgen(js_name = SessionKeys)]
#[derive(Clone, Copy)]
pub struct WASMSessionKeys {
    pseudonym: WASMPseudonymSessionKeys,
    attribute: WASMAttributeSessionKeys,
}

#[wasm_bindgen(js_class = "SessionKeys")]
impl WASMSessionKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonym: WASMPseudonymSessionKeys, attribute: WASMAttributeSessionKeys) -> Self {
        Self {
            pseudonym,
            attribute,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymSessionKeys {
        self.pseudonym
    }

    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeSessionKeys {
        self.attribute
    }
}

impl From<WASMSessionKeys> for SessionKeys {
    fn from(keys: WASMSessionKeys) -> Self {
        SessionKeys {
            pseudonym: PseudonymSessionKeys {
                public: keys.pseudonym.public.0 .0.into(),
                secret: keys.pseudonym.secret.0 .0.into(),
            },
            attribute: AttributeSessionKeys {
                public: keys.attribute.public.0 .0.into(),
                secret: keys.attribute.secret.0 .0.into(),
            },
        }
    }
}

impl From<SessionKeys> for WASMSessionKeys {
    fn from(keys: SessionKeys) -> Self {
        WASMSessionKeys {
            pseudonym: WASMPseudonymSessionKeys {
                public: WASMPseudonymSessionPublicKey(WASMGroupElement::from(
                    keys.pseudonym.public.0,
                )),
                secret: WASMPseudonymSessionSecretKey(WASMScalarNonZero::from(
                    keys.pseudonym.secret.0,
                )),
            },
            attribute: WASMAttributeSessionKeys {
                public: WASMAttributeSessionPublicKey(WASMGroupElement::from(
                    keys.attribute.public.0,
                )),
                secret: WASMAttributeSessionSecretKey(WASMScalarNonZero::from(
                    keys.attribute.secret.0,
                )),
            },
        }
    }
}
