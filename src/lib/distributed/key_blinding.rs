//! Key blinding, session key share generation and session key retrieval for distributed trust.

use crate::high_level::keys::*;
use crate::internal::arithmetic::*;
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);

/// A blinded global secret key, which is the global secret key blinded by the blinding factors from
/// all transcryptors, making it impossible to see or derive other keys from it without cooperation
/// of the transcryptors.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlindedGlobalSecretKey(pub(crate) ScalarNonZero);

/// A session key share, which a part a session key provided by one transcryptor.
/// By combining all session key shares and the [`BlindedGlobalSecretKey`], a session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SessionKeyShare(pub(crate) ScalarNonZero);

/// A trait for scalars that are safe to encode and decode since they do not need to remain absolutely secret.
pub trait SafeScalar {
    /// Create from a scalar.
    fn from(x: ScalarNonZero) -> Self;
    /// Get the scalar value.
    fn value(&self) -> &ScalarNonZero;
    /// Encode as a byte array.
    /// See [`ScalarNonZero::encode`] for more information.
    fn encode(&self) -> [u8; 32] {
        self.value().encode()
    }
    /// Decode from a byte array.
    /// Returns `None` if the array is not 32 bytes long.
    /// See [`ScalarNonZero::decode`] for more information.
    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode(bytes).map(Self::from)
    }
    /// Decode from a slice of bytes.
    /// Returns `None` if the slice is not 32 bytes long.
    /// See [`ScalarNonZero::decode_from_slice`] for more information.
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode_from_slice(slice).map(Self::from)
    }
    /// Decode from a hexadecimal string of 64 characters.
    /// Returns `None` if the string is not 64 characters long.
    /// See [`ScalarNonZero::decode_from_hex`] for more information.
    fn decode_from_hex(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ScalarNonZero::decode_from_hex(s).map(Self::from)
    }
    /// Encode as a hexadecimal string of 64 characters.
    /// See [`ScalarNonZero::encode_as_hex`] for more information.
    fn encode_as_hex(&self) -> String {
        self.value().encode_as_hex()
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
    /// Create a random blinding factor.
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
        serializer.serialize_str(self.encode_as_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for BlindedGlobalSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlindedGlobalSecretKeyVisitor;
        impl Visitor<'_> for BlindedGlobalSecretKeyVisitor {
            type Value = BlindedGlobalSecretKey;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a BlindedGlobalSecretKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(v)
                    .map(BlindedGlobalSecretKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
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
        serializer.serialize_str(self.encode_as_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for SessionKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SessionKeyShareVisitor;
        impl Visitor<'_> for SessionKeyShareVisitor {
            type Value = SessionKeyShare;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a SessionKeyShare")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(v)
                    .map(SessionKeyShare)
                    .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(SessionKeyShareVisitor)
    }
}

/// Create a [`BlindedGlobalSecretKey`] from a [`GlobalSecretKey`] and a list of [`BlindingFactor`]s.
/// Used during system setup to blind the global secret key.
/// Returns `None` if the product of all blinding factors accidentally turns out to be 1.
pub fn make_blinded_global_secret_key(
    global_secret_key: &GlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedGlobalSecretKey> {
    let y = *global_secret_key;
    let k = blinding_factors
        .iter()
        .fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert());
    if k == ScalarNonZero::one() {
        return None;
    }
    Some(BlindedGlobalSecretKey(y.0 * k))
}

/// Create a [`SessionKeyShare`] from a [`ScalarNonZero`] rekey factor and a [`BlindingFactor`].
pub fn make_session_key_share(
    rekey_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShare {
    SessionKeyShare(rekey_factor * blinding_factor.0)
}

/// Reconstruct a session key from a [`BlindedGlobalSecretKey`] and a list of [`SessionKeyShare`]s.
pub fn make_session_key(
    blinded_global_secret_key: BlindedGlobalSecretKey,
    session_key_shares: &[SessionKeyShare],
) -> (SessionPublicKey, SessionSecretKey) {
    let secret = SessionSecretKey::from(
        session_key_shares
            .iter()
            .fold(blinded_global_secret_key.0, |acc, x| acc * x.0),
    );
    let public = SessionPublicKey::from(secret.0 * G);
    (public, secret)
}

/// Update a session key share from one session to the other
pub fn update_session_key(
    session_secret_key: SessionSecretKey,
    old_session_key_share: SessionKeyShare,
    new_session_key_share: SessionKeyShare,
) -> (SessionPublicKey, SessionSecretKey) {
    let secret = SessionSecretKey::from(
        session_secret_key.0 * old_session_key_share.0.invert() * new_session_key_share.0,
    );
    let public = SessionPublicKey::from(secret.0 * G);
    (public, secret)
}

/// Setup a distributed system with a global public key, a blinded global secret key and a list of
/// blinding factors.
/// The blinding factors should securely be transferred to the transcryptors ([`PEPSystem`](crate::distributed::systems::PEPSystem)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`PEPClient`](crate::distributed::systems::PEPClient)s.
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
