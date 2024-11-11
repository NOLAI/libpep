use crate::high_level::keys::*;
use crate::internal::arithmetic::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

#[derive(Copy, Clone, Debug, From)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct BlindedGlobalSecretKey(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct SessionKeyShare(pub(crate) ScalarNonZero);
impl BlindingFactor {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = ScalarNonZero::random(rng);
        assert_ne!(scalar, ScalarNonZero::one());
        BlindingFactor(scalar)
    }
    pub fn from(x: ScalarNonZero) -> Self {
        BlindingFactor(x)
    }
    pub fn encode(&self) -> [u8; 32] {
        self.0.encode()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::decode(bytes).map(BlindingFactor)
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        hex::decode(s).ok().and_then(|bytes| {
            if bytes.len() == 32 {
                Some(
                    BlindingFactor::decode(<&[u8; 32]>::try_from(bytes.as_slice()).unwrap())
                        .unwrap(),
                )
            } else {
                None
            }
        })
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
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
    key_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShare {
    SessionKeyShare(key_factor * blinding_factor.0)
}

pub fn make_session_key(
    blinded_global_secret_key: BlindedGlobalSecretKey,
    session_key_shares: &[SessionKeyShare],
) -> (SessionPublicKey, SessionSecretKey) {
    let secret = SessionSecretKey::from(
        session_key_shares
            .iter()
            .fold(*blinded_global_secret_key, |acc, x| acc * x.deref()),
    );
    let public = SessionPublicKey::from(secret.0 * &G);
    (public, secret)
}
