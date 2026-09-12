use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::arithmetic::scalars::WASMScalarNonZero;
use crate::macros::{wasm_pair_impl, wasm_point_key_impl};
use derive_more::{Deref, From, Into};
use libpep::keys::types::*;
use libpep::keys::PublicKey;
use libpep::keys::SecretKey;
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
wasm_point_key_impl!(WASMPseudonymGlobalPublicKey as "PseudonymGlobalPublicKey");

/// An attribute global public key from which attribute session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = AttributeGlobalPublicKey)]
pub struct WASMAttributeGlobalPublicKey(pub WASMGroupElement);
wasm_point_key_impl!(WASMAttributeGlobalPublicKey as "AttributeGlobalPublicKey");

/// Pseudonym session key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymSessionKeyPair)]
pub struct WASMPseudonymSessionKeyPair {
    public: WASMPseudonymSessionPublicKey,
    secret: WASMPseudonymSessionSecretKey,
}
wasm_pair_impl!(WASMPseudonymSessionKeyPair as "PseudonymSessionKeyPair" {
    public: WASMPseudonymSessionPublicKey,
    secret: WASMPseudonymSessionSecretKey
});

/// Attribute session key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = AttributeSessionKeyPair)]
pub struct WASMAttributeSessionKeyPair {
    public: WASMAttributeSessionPublicKey,
    secret: WASMAttributeSessionSecretKey,
}
wasm_pair_impl!(WASMAttributeSessionKeyPair as "AttributeSessionKeyPair" {
    public: WASMAttributeSessionPublicKey,
    secret: WASMAttributeSessionSecretKey
});

/// Pseudonym global key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymGlobalKeyPair)]
pub struct WASMPseudonymGlobalKeyPair {
    public: WASMPseudonymGlobalPublicKey,
    secret: WASMPseudonymGlobalSecretKey,
}
wasm_pair_impl!(WASMPseudonymGlobalKeyPair as "PseudonymGlobalKeyPair" {
    public: WASMPseudonymGlobalPublicKey,
    secret: WASMPseudonymGlobalSecretKey
}, js_constructor);

/// Attribute global key pair.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = AttributeGlobalKeyPair)]
pub struct WASMAttributeGlobalKeyPair {
    public: WASMAttributeGlobalPublicKey,
    secret: WASMAttributeGlobalSecretKey,
}
wasm_pair_impl!(WASMAttributeGlobalKeyPair as "AttributeGlobalKeyPair" {
    public: WASMAttributeGlobalPublicKey,
    secret: WASMAttributeGlobalSecretKey
}, js_constructor);

/// Combined global public keys for both pseudonyms and attributes.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalPublicKeys)]
pub struct WASMGlobalPublicKeys {
    pseudonym: WASMPseudonymGlobalPublicKey,
    attribute: WASMAttributeGlobalPublicKey,
}
wasm_pair_impl!(WASMGlobalPublicKeys as "GlobalPublicKeys" {
    pseudonym: WASMPseudonymGlobalPublicKey,
    attribute: WASMAttributeGlobalPublicKey
}, js_constructor);

/// Combined global secret keys for both pseudonyms and attributes.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalSecretKeys)]
pub struct WASMGlobalSecretKeys {
    pseudonym: WASMPseudonymGlobalSecretKey,
    attribute: WASMAttributeGlobalSecretKey,
}
wasm_pair_impl!(WASMGlobalSecretKeys as "GlobalSecretKeys" {
    pseudonym: WASMPseudonymGlobalSecretKey,
    attribute: WASMAttributeGlobalSecretKey
}, js_constructor);

/// Combined global key pairs for both pseudonyms and attributes.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalKeyPairs)]
pub struct WASMGlobalKeyPairs {
    public: WASMGlobalPublicKeys,
    secret: WASMGlobalSecretKeys,
}
wasm_pair_impl!(WASMGlobalKeyPairs as "GlobalKeyPairs" {
    public: WASMGlobalPublicKeys,
    secret: WASMGlobalSecretKeys
}, js_constructor);

/// Session keys for encrypting and decrypting data.
/// Pseudonym session keys containing both public and secret keys.
#[wasm_bindgen(js_name = PseudonymSessionKeys)]
#[derive(Clone, Copy)]
pub struct WASMPseudonymSessionKeys {
    public: WASMPseudonymSessionPublicKey,
    secret: WASMPseudonymSessionSecretKey,
}
wasm_pair_impl!(WASMPseudonymSessionKeys as "PseudonymSessionKeys" {
    public: WASMPseudonymSessionPublicKey,
    secret: WASMPseudonymSessionSecretKey
}, js_constructor);

/// Attribute session keys containing both public and secret keys.
#[wasm_bindgen(js_name = AttributeSessionKeys)]
#[derive(Clone, Copy)]
pub struct WASMAttributeSessionKeys {
    public: WASMAttributeSessionPublicKey,
    secret: WASMAttributeSessionSecretKey,
}
wasm_pair_impl!(WASMAttributeSessionKeys as "AttributeSessionKeys" {
    public: WASMAttributeSessionPublicKey,
    secret: WASMAttributeSessionSecretKey
}, js_constructor);

/// Session keys for both pseudonyms and attributes.
/// Contains both pseudonym and attribute session keys (public and secret).
#[wasm_bindgen(js_name = SessionKeys)]
#[derive(Clone, Copy)]
pub struct WASMSessionKeys {
    pseudonym: WASMPseudonymSessionKeys,
    attribute: WASMAttributeSessionKeys,
}
wasm_pair_impl!(WASMSessionKeys as "SessionKeys" {
    pseudonym: WASMPseudonymSessionKeys,
    attribute: WASMAttributeSessionKeys
}, js_constructor);

impl From<WASMSessionKeys> for SessionKeys {
    fn from(keys: WASMSessionKeys) -> Self {
        SessionKeys {
            pseudonym: PseudonymSessionKeys {
                public: PseudonymSessionPublicKey::from_point(keys.pseudonym.public.0 .0),
                secret: PseudonymSessionSecretKey::from_scalar(keys.pseudonym.secret.0 .0),
            },
            attribute: AttributeSessionKeys {
                public: AttributeSessionPublicKey::from_point(keys.attribute.public.0 .0),
                secret: AttributeSessionSecretKey::from_scalar(keys.attribute.secret.0 .0),
            },
        }
    }
}

impl From<SessionKeys> for WASMSessionKeys {
    fn from(keys: SessionKeys) -> Self {
        WASMSessionKeys {
            pseudonym: WASMPseudonymSessionKeys {
                public: WASMPseudonymSessionPublicKey(WASMGroupElement::from(
                    *keys.pseudonym.public,
                )),
                secret: WASMPseudonymSessionSecretKey(WASMScalarNonZero::from(
                    *keys.pseudonym.secret.value(),
                )),
            },
            attribute: WASMAttributeSessionKeys {
                public: WASMAttributeSessionPublicKey(WASMGroupElement::from(
                    *keys.attribute.public,
                )),
                secret: WASMAttributeSessionSecretKey(WASMScalarNonZero::from(
                    *keys.attribute.secret.value(),
                )),
            },
        }
    }
}
