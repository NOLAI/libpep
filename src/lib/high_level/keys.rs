//! Generation of global keys (only for system configuration) and session keys (only for 1-PEP),
//! and pseudonymization and rekeying secrets to be used for transcryption.
//!
//! Keys are split into separate Attribute and Pseudonym encryption keys for enhanced security.

use crate::high_level::contexts::EncryptionContext;
use crate::high_level::secrets::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, EncryptionSecret,
};
use crate::internal::arithmetic::{GroupElement, ScalarNonZero, ScalarTraits, G};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

/// A global public key for pseudonyms, associated with the [`PseudonymGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt pseudonyms against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct PseudonymGlobalPublicKey(pub GroupElement);
/// A global secret key for pseudonyms from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
pub struct PseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

/// A global public key for attributes, associated with the [`AttributeGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt attributes against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct AttributeGlobalPublicKey(pub GroupElement);
/// A global secret key for attributes from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
pub struct AttributeGlobalSecretKey(pub(crate) ScalarNonZero);

/// A session public key used to encrypt pseudonyms against, associated with a [`PseudonymSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct PseudonymSessionPublicKey(pub GroupElement);
/// A session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Debug, From)]
pub struct PseudonymSessionSecretKey(pub(crate) ScalarNonZero);

/// A session public key used to encrypt attributes against, associated with a [`AttributeSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct AttributeSessionPublicKey(pub GroupElement);
/// A session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Debug, From)]
pub struct AttributeSessionSecretKey(pub(crate) ScalarNonZero);

impl Serialize for PseudonymSessionSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.encode_as_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for PseudonymSessionSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PseudonymSessionSecretKeyVisitor;
        impl Visitor<'_> for PseudonymSessionSecretKeyVisitor {
            type Value = PseudonymSessionSecretKey;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a PseudonymSessionSecretKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(v)
                    .map(PseudonymSessionSecretKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(PseudonymSessionSecretKeyVisitor)
    }
}

impl Serialize for AttributeSessionSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.encode_as_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for AttributeSessionSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttributeSessionSecretKeyVisitor;
        impl Visitor<'_> for AttributeSessionSecretKeyVisitor {
            type Value = AttributeSessionSecretKey;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a AttributeSessionSecretKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(v)
                    .map(AttributeSessionSecretKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(AttributeSessionSecretKeyVisitor)
    }
}

/// A trait for public keys, which can be encoded and decoded from byte arrays and hex strings.
pub trait PublicKey {
    fn value(&self) -> &GroupElement;
    fn encode(&self) -> [u8; 32] {
        self.value().encode()
    }
    fn as_hex(&self) -> String {
        self.value().encode_as_hex()
    }
    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized;
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized;
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized;
}
/// A trait for secret keys, for which we do not allow encoding as secret keys should not be shared.
pub trait SecretKey {
    fn value(&self) -> &ScalarNonZero; // TODO should this be public (or only under the `insecure-methods` feature)?
}
impl PublicKey for PseudonymGlobalPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }

    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode(bytes).map(Self::from)
    }
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_slice(slice).map(PseudonymGlobalPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_hex(s).map(PseudonymGlobalPublicKey::from)
    }
}
impl SecretKey for PseudonymGlobalSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl PublicKey for AttributeGlobalPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }

    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode(bytes).map(Self::from)
    }
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_slice(slice).map(AttributeGlobalPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_hex(s).map(AttributeGlobalPublicKey::from)
    }
}
impl SecretKey for AttributeGlobalSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl PublicKey for PseudonymSessionPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode(bytes).map(Self::from)
    }
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_slice(slice).map(PseudonymSessionPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_hex(s).map(PseudonymSessionPublicKey::from)
    }
}
impl SecretKey for PseudonymSessionSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl PublicKey for AttributeSessionPublicKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode(bytes).map(Self::from)
    }
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_slice(slice).map(AttributeSessionPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_hex(s).map(AttributeSessionPublicKey::from)
    }
}
impl SecretKey for AttributeSessionSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

/// Generate a new global key pair for pseudonyms.
pub fn make_pseudonym_global_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (PseudonymGlobalPublicKey, PseudonymGlobalSecretKey) {
    let sk = loop {
        let sk = ScalarNonZero::random(rng);
        if sk != ScalarNonZero::one() {
            break sk;
        }
    };
    let pk = sk * G;
    (PseudonymGlobalPublicKey(pk), PseudonymGlobalSecretKey(sk))
}

/// Generate a new global key pair for attributes.
pub fn make_attribute_global_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (AttributeGlobalPublicKey, AttributeGlobalSecretKey) {
    let sk = loop {
        let sk = ScalarNonZero::random(rng);
        if sk != ScalarNonZero::one() {
            break sk;
        }
    };
    let pk = sk * G;
    (AttributeGlobalPublicKey(pk), AttributeGlobalSecretKey(sk))
}

/// Generate session keys for pseudonyms from a [`PseudonymGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_pseudonym_session_keys(
    global: &PseudonymGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    let k = make_pseudonym_rekey_factor(secret, context);
    let sk = k.0 * global.0;
    let pk = sk * G;
    (PseudonymSessionPublicKey(pk), PseudonymSessionSecretKey(sk))
}

/// Generate session keys for attributes from a [`AttributeGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_attribute_session_keys(
    global: &AttributeGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    let k = make_attribute_rekey_factor(secret, context);
    let sk = k.0 * global.0;
    let pk = sk * G;
    (AttributeSessionPublicKey(pk), AttributeSessionSecretKey(sk))
}
