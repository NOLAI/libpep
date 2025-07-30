//! Generation of global keys (only for system configuration) and session keys (only for 1-PEP),
//! and pseudonymization and rekeying secrets to be used for transcryption.

use crate::high_level::contexts::EncryptionContext;
use crate::high_level::utils::make_rekey_factor;
use crate::internal::arithmetic::{GroupElement, ScalarNonZero, ScalarTraits, G};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

/// A global public key associated with the [`GlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt messages against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct GlobalPublicKey(pub GroupElement);
/// A global secret key from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
pub struct GlobalSecretKey(pub(crate) ScalarNonZero);

/// A session public key used to encrypt messages against, associated with a [`SessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct SessionPublicKey(pub GroupElement);
/// A session secret key used to decrypt messages with.
#[derive(Copy, Clone, Debug, From)]
pub struct SessionSecretKey(pub(crate) ScalarNonZero);

impl Serialize for SessionSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.encode_as_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for SessionSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SessionSecretKeyVisitor;
        impl Visitor<'_> for SessionSecretKeyVisitor {
            type Value = SessionSecretKey;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a SessionSecretKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(v)
                    .map(SessionSecretKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(SessionSecretKeyVisitor)
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
impl PublicKey for GlobalPublicKey {
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
        GroupElement::decode_from_slice(slice).map(GlobalPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_hex(s).map(GlobalPublicKey::from)
    }
}
impl SecretKey for GlobalSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl PublicKey for SessionPublicKey {
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
        GroupElement::decode_from_slice(slice).map(SessionPublicKey::from)
    }
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_hex(s).map(SessionPublicKey::from)
    }
}
impl SecretKey for SessionSecretKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from contexts.
pub type Secret = Box<[u8]>;
/// Pseudonymization secret used to derive a [`ReshuffleFactor`](crate::high_level::contexts::ReshuffleFactor) from a [`PseudonymizationContext`](crate::high_level::contexts::PseudonymizationDomain) (see [`PseudonymizationInfo`](crate::high_level::contexts::PseudonymizationInfo)).
#[derive(Clone, Debug, From)]
pub struct PseudonymizationSecret(pub(crate) Secret);
/// Encryption secret used to derive a [`RekeyFactor`](crate::high_level::contexts::RekeyFactor) from an [`EncryptionContext`] (see [`RekeyInfo`](crate::high_level::contexts::RekeyInfo)).
#[derive(Clone, Debug, From)]
pub struct EncryptionSecret(pub(crate) Secret);
impl PseudonymizationSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}
impl EncryptionSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}

/// Generate a new global key pair.
pub fn make_global_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (GlobalPublicKey, GlobalSecretKey) {
    let sk = loop {
        let sk = ScalarNonZero::random(rng);
        if sk != ScalarNonZero::one() {
            break sk;
        }
    };
    let pk = sk * G;
    (GlobalPublicKey(pk), GlobalSecretKey(sk))
}

/// Generate session keys from a [`GlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_session_keys(
    global: &GlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (SessionPublicKey, SessionSecretKey) {
    let k = make_rekey_factor(secret, context);
    let sk = k.0 * global.0;
    let pk = sk * G;
    (SessionPublicKey(pk), SessionSecretKey(sk))
}
