//! Key blinding, session key share generation and session key retrieval for distributed trust.

use crate::high_level::keys::*;
use crate::internal::arithmetic::*;
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

#[derive(Copy, Clone, Debug)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlindedGlobalSecretKey(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SessionKeyShare(pub(crate) ScalarNonZero);
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
impl SafeScalar for BlindedGlobalSecretKey {
    fn from(x: ScalarNonZero) -> Self {
        BlindedGlobalSecretKey(x)
    }

    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl SafeScalar for SessionKeyShare {
    fn from(x: ScalarNonZero) -> Self {
        SessionKeyShare(x)
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

impl Serialize for BlindedGlobalSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode_to_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for BlindedGlobalSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlindedGlobalSecretKeyVisitor;
        impl<'de> Visitor<'de> for BlindedGlobalSecretKeyVisitor {
            type Value = BlindedGlobalSecretKey;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a BlindedGlobalSecretKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(&v)
                    .map(BlindedGlobalSecretKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(BlindedGlobalSecretKeyVisitor)
    }
}
impl Serialize for SessionKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode_to_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for SessionKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SessionKeyShareVisitor;
        impl<'de> Visitor<'de> for SessionKeyShareVisitor {
            type Value = SessionKeyShare;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a SessionKeyShare")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(&v)
                    .map(SessionKeyShare)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(SessionKeyShareVisitor)
    }
}

pub fn make_blinded_global_secret_key(
    global_secret_key: &GlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedGlobalSecretKey> {
    let y = global_secret_key.clone();
    let k = blinding_factors
        .iter()
        .fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert());
    if k == ScalarNonZero::one() {
        return None;
    }
    Some(BlindedGlobalSecretKey(y.0 * k))
}

pub fn make_session_key_share(
    rekey_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShare {
    SessionKeyShare(rekey_factor * blinding_factor.0)
}

pub fn make_session_key(
    blinded_global_secret_key: BlindedGlobalSecretKey,
    session_key_shares: &[SessionKeyShare],
) -> (SessionPublicKey, SessionSecretKey) {
    let secret = SessionSecretKey::from(
        session_key_shares
            .iter()
            .fold(blinded_global_secret_key.0, |acc, x| acc * x.0),
    );
    let public = SessionPublicKey::from(secret.0 * &G);
    (public, secret)
}

pub fn make_distributed_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (GlobalPublicKey, BlindedGlobalSecretKey, Vec<BlindingFactor>) {
    let (pk, sk) = make_global_keys(rng);
    let blinding_factors: Vec<BlindingFactor> =
        (0..n).map(|_| BlindingFactor::random(rng)).collect();
    let bsk = make_blinded_global_secret_key(&sk, &blinding_factors).unwrap();
    (pk, bsk, blinding_factors)
}
