//! The ElGamal ciphertext and its encryption and decryption, generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use base64::engine::general_purpose;
use base64::Engine;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::de::{Error, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use std::fmt::Formatter;
use std::hash::Hash;

/// An ElGamal ciphertext over the group `G`: the pair `(B, C)`, and with the `elgamal3` feature
/// also the public key `Y` it was encrypted under.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ElGamal<G: Group> {
    pub gb: G::Element,
    pub gc: G::Element,
    #[cfg(feature = "elgamal3")]
    pub gy: G::Element,
}

impl<G: Group> ElGamal<G> {
    /// The length of a serialized ciphertext in bytes: two (with `elgamal3`: three) serialized
    /// group elements.
    #[cfg(not(feature = "elgamal3"))]
    pub const LENGTH: usize = 2 * G::NE;
    /// The length of a serialized ciphertext in bytes: two (with `elgamal3`: three) serialized
    /// group elements.
    #[cfg(feature = "elgamal3")]
    pub const LENGTH: usize = 3 * G::NE;

    /// Decode from a byte slice of exactly [`LENGTH`](Self::LENGTH) bytes: the concatenation of
    /// the serialized elements. Returns `None` for any other length, for a component that is
    /// not a valid encoding of a group element, and for the identity element.
    pub fn from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != Self::LENGTH {
            return None;
        }
        let ne = G::NE;
        Some(Self {
            gb: G::deserialize_element(&v[0..ne])?,
            gc: G::deserialize_element(&v[ne..2 * ne])?,
            #[cfg(feature = "elgamal3")]
            gy: G::deserialize_element(&v[2 * ne..3 * ne])?,
        })
    }

    /// Encode as [`LENGTH`](Self::LENGTH) bytes: the concatenation of the serialized elements.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LENGTH);
        out.extend_from_slice(G::serialize_element(&self.gb).as_ref());
        out.extend_from_slice(G::serialize_element(&self.gc).as_ref());
        #[cfg(feature = "elgamal3")]
        out.extend_from_slice(G::serialize_element(&self.gy).as_ref());
        out
    }

    /// Encode as a URL-safe base64 string.
    pub fn to_base64(&self) -> String {
        general_purpose::URL_SAFE.encode(self.to_bytes())
    }

    /// Decode from a URL-safe base64 string.
    pub fn from_base64(s: &str) -> Option<Self> {
        general_purpose::URL_SAFE
            .decode(s)
            .ok()
            .and_then(|v| Self::from_slice(&v))
    }
}

#[cfg(feature = "serde")]
impl<G: Group> Serialize for ElGamal<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_base64().as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group> Deserialize<'de> for ElGamal<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ElGamalVisitor<G>(std::marker::PhantomData<G>);
        impl<G: Group> Visitor<'_> for ElGamalVisitor<G> {
            type Value = ElGamal<G>;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 encoded string representing an ElGamal ciphertext")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ElGamal::from_base64(v)
                    .ok_or(E::custom(format!("invalid base64 encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(ElGamalVisitor(std::marker::PhantomData))
    }
}

/// Encrypt message `gm` under public key `gy`, with randomness from `rng`.
///
/// Encryption under the identity element as public key would send the message in the clear; it
/// is rejected with an assertion.
pub fn encrypt<G: Group, R: Rng + CryptoRng>(
    gm: &G::Element,
    gy: &G::Element,
    rng: &mut R,
) -> ElGamal<G> {
    assert_ne!(gy, &G::identity());
    let r = G::random_scalar(rng);
    ElGamal {
        gb: G::scalar_mult_gen(&r),
        gc: *gm + r * *gy,
        #[cfg(feature = "elgamal3")]
        gy: *gy,
    }
}

/// Decrypt a ciphertext encrypted under `y * G` with secret key `y`.
/// With the `elgamal3` feature, returns `None` if the secret key does not match the public key
/// the ciphertext was encrypted under.
#[cfg(feature = "elgamal3")]
pub fn decrypt<G: Group>(encrypted: &ElGamal<G>, y: &G::Scalar) -> Option<G::Element> {
    if G::scalar_mult_gen(y) != encrypted.gy {
        return None;
    }
    Some(encrypted.gc - *y * encrypted.gb)
}

/// Decrypt a ciphertext encrypted under `y * G` with secret key `y`.
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt<G: Group>(encrypted: &ElGamal<G>, y: &G::Scalar) -> G::Element {
    encrypted.gc - *y * encrypted.gb
}
