use crate::high_level::keys::*;
use crate::internal::arithmetic::*;
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

#[derive(Copy, Clone, Debug)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlindedGlobalSecretEncryptionKey(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SessionEncryptionKeyShare(pub(crate) ScalarNonZero);
pub trait SafeScalar {
    fn from(x: ScalarNonZero) -> Self;
    fn value(&self) -> &ScalarNonZero;
    fn encode(&self) -> [u8; 32] {
        self.value().encode()
    }
    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode(bytes).map(Self::from)
    }
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode_from_slice(slice).map(Self::from)
    }
    fn decode_from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode_from_hex(s).map(Self::from)
    }
    fn encode_to_hex(&self) -> String {
        self.value().encode_to_hex()
    }
}
impl SafeScalar for BlindingFactor {
    fn from(x: ScalarNonZero) -> Self {
        BlindingFactor(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl SafeScalar for BlindedGlobalSecretEncryptionKey {
    fn from(x: ScalarNonZero) -> Self {
        BlindedGlobalSecretEncryptionKey(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl SafeScalar for SessionEncryptionKeyShare {
    fn from(x: ScalarNonZero) -> Self {
        SessionEncryptionKeyShare(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl BlindingFactor {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = ScalarNonZero::random(rng);
        assert_ne!(scalar, ScalarNonZero::one());
        Self(scalar)
    }
}

impl Serialize for BlindedGlobalSecretEncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode_to_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for BlindedGlobalSecretEncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlindedGlobalSecretKeyVisitor;
        impl<'de> Visitor<'de> for BlindedGlobalSecretKeyVisitor {
            type Value = BlindedGlobalSecretEncryptionKey;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a BlindedGlobalSecretKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(&v)
                    .map(BlindedGlobalSecretEncryptionKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(BlindedGlobalSecretKeyVisitor)
    }
}
impl Serialize for SessionEncryptionKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode_to_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for SessionEncryptionKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SessionKeyShareVisitor;
        impl<'de> Visitor<'de> for SessionKeyShareVisitor {
            type Value = SessionEncryptionKeyShare;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a SessionKeyShare")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(&v)
                    .map(SessionEncryptionKeyShare)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(SessionKeyShareVisitor)
    }
}

pub fn make_blinded_global_secret_key(
    global_secret_key: &GlobalSecretEncryptionKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedGlobalSecretEncryptionKey> {
    let y = global_secret_key.clone();
    let k = blinding_factors
        .iter()
        .fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert());
    if k == ScalarNonZero::one() {
        return None;
    }
    Some(BlindedGlobalSecretEncryptionKey(y.0 * k))
}

pub fn make_session_key_share(
    key_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> SessionEncryptionKeyShare {
    SessionEncryptionKeyShare(key_factor * blinding_factor.0)
}

pub fn make_session_encryption_key(
    blinded_global_secret_key: BlindedGlobalSecretEncryptionKey,
    session_key_shares: &[SessionEncryptionKeyShare],
) -> (SessionPublicEncryptionKey, SessionSecretEncryptionKey) {
    let secret = SessionSecretEncryptionKey::from(
        session_key_shares
            .iter()
            .fold(blinded_global_secret_key.0, |acc, x| acc * x.0),
    );
    let public = SessionPublicEncryptionKey::from(secret.0 * &G);
    (public, secret)
}
