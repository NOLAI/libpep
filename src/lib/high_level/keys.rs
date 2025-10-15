//! Generation of global keys (only for system configuration) and session keys (only for 1-PEP),
//! and pseudonymization and rekeying secrets to be used for transcryption.
//!
//! Keys are split into separate Attribute and Pseudonym encryption keys for enhanced security.

use crate::high_level::contexts::{EncryptionContext, RekeyFactor};
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
pub struct PseudonymGlobalPublicKey(pub(crate) GroupElement);
/// A global secret key for pseudonyms from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
pub struct PseudonymGlobalSecretKey(pub(crate) ScalarNonZero);

/// A global public key for attributes, associated with the [`AttributeGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt attributes against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct AttributeGlobalPublicKey(pub(crate) GroupElement);
/// A global secret key for attributes from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
pub struct AttributeGlobalSecretKey(pub(crate) ScalarNonZero);

/// A pair of global public keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct GlobalPublicKeys {
    pub pseudonym: PseudonymGlobalPublicKey,
    pub attribute: AttributeGlobalPublicKey,
}

/// A pair of global secret keys containing both pseudonym and attribute keys.
#[derive(Copy, Clone, Debug)]
pub struct GlobalSecretKeys {
    pub pseudonym: PseudonymGlobalSecretKey,
    pub attribute: AttributeGlobalSecretKey,
}

/// A session public key used to encrypt pseudonyms against, associated with a [`PseudonymSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct PseudonymSessionPublicKey(pub(crate) GroupElement);
/// A session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Debug, From, Eq, PartialEq)]
pub struct PseudonymSessionSecretKey(pub(crate) ScalarNonZero);

/// A session public key used to encrypt attributes against, associated with a [`AttributeSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct AttributeSessionPublicKey(pub(crate) GroupElement);
/// A session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Debug, From, Eq, PartialEq)]
pub struct AttributeSessionSecretKey(pub(crate) ScalarNonZero);

/// A pseudonym session key pair containing both public and secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Serialize, Deserialize)]
pub struct PseudonymSessionKeys {
    pub public: PseudonymSessionPublicKey,
    pub secret: PseudonymSessionSecretKey,
}

/// An attribute session key pair containing both public and secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Serialize, Deserialize)]
pub struct AttributeSessionKeys {
    pub public: AttributeSessionPublicKey,
    pub secret: AttributeSessionSecretKey,
}

/// Session keys for both pseudonyms and attributes.
/// Organized by key type (pseudonym/attribute) rather than by public/secret.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Serialize, Deserialize)]
pub struct SessionKeys {
    pub pseudonym: PseudonymSessionKeys,
    pub attribute: AttributeSessionKeys,
}

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

/// Generic key generation for global keys.
fn _make_global_keys<R, PK, SK>(rng: &mut R) -> (PK, SK)
where
    R: RngCore + CryptoRng,
    PK: From<GroupElement>,
    SK: From<ScalarNonZero>,
{
    let sk = loop {
        let sk = ScalarNonZero::random(rng);
        if sk != ScalarNonZero::one() {
            break sk;
        }
    };
    let pk = sk * G;
    (PK::from(pk), SK::from(sk))
}

/// Generate new global key pairs for both pseudonyms and attributes.
pub fn make_global_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (GlobalPublicKeys, GlobalSecretKeys) {
    let (pseudonym_pk, pseudonym_sk) = _make_global_keys(rng);
    let (attribute_pk, attribute_sk) = _make_global_keys(rng);
    (
        GlobalPublicKeys {
            pseudonym: pseudonym_pk,
            attribute: attribute_pk,
        },
        GlobalSecretKeys {
            pseudonym: pseudonym_sk,
            attribute: attribute_sk,
        },
    )
}

/// Generate a new global key pair for pseudonyms.
pub fn make_pseudonym_global_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (PseudonymGlobalPublicKey, PseudonymGlobalSecretKey) {
    _make_global_keys(rng)
}

/// Generate a new global key pair for attributes.
pub fn make_attribute_global_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (AttributeGlobalPublicKey, AttributeGlobalSecretKey) {
    _make_global_keys(rng)
}

/// Generic session key generation.
fn _make_session_keys<GSK, PK, SK, RF, F>(
    global: &GSK,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
    rekey_fn: F,
) -> (PK, SK)
where
    GSK: SecretKey,
    PK: From<GroupElement>,
    SK: From<ScalarNonZero>,
    RF: RekeyFactor,
    F: Fn(&EncryptionSecret, &EncryptionContext) -> RF,
{
    let k = rekey_fn(secret, context);
    let sk = k.scalar() * *global.value();
    let pk = sk * G;
    (PK::from(pk), SK::from(sk))
}

/// Generate session keys for both pseudonyms and attributes from [`GlobalSecretKeys`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_session_keys(
    global: &GlobalSecretKeys,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> SessionKeys {
    let (pseudonym_public, pseudonym_secret) = _make_session_keys(
        &global.pseudonym,
        context,
        secret,
        make_pseudonym_rekey_factor,
    );
    let (attribute_public, attribute_secret) = _make_session_keys(
        &global.attribute,
        context,
        secret,
        make_attribute_rekey_factor,
    );

    SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Generate session keys for pseudonyms from a [`PseudonymGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_pseudonym_session_keys(
    global: &PseudonymGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    _make_session_keys(global, context, secret, make_pseudonym_rekey_factor)
}

/// Generate session keys for attributes from a [`AttributeGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_attribute_session_keys(
    global: &AttributeGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    _make_session_keys(global, context, secret, make_attribute_rekey_factor)
}
