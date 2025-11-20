use curve25519_dalek_libpep::ristretto::CompressedRistretto;
use curve25519_dalek_libpep::ristretto::RistrettoPoint;
use curve25519_dalek_libpep::traits::Identity;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::de::{Error, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::fmt::Formatter;
use std::hash::Hash;

/// The base point constant so that a [ScalarNonZero]/[ScalarCanBeZero] s can be converted to a [GroupElement] by performing `s * G`.
pub const G: GroupElement =
    GroupElement(curve25519_dalek_libpep::constants::RISTRETTO_BASEPOINT_POINT);

/// Element on a group. Can not be converted to a scalar. Supports addition and subtraction. Multiplication by a scalar is supported.
/// We use ristretto points to discard unsafe points and safely use the group operations in higher level protocols without any other cryptographic assumptions.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GroupElement(pub(crate) RistrettoPoint);

impl GroupElement {
    /// Generate a random GroupElement. This is the preferred way of generating pseudonyms.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(RistrettoPoint::random(rng))
    }

    /// Decode a 32-byte compressed Ristretto point.
    /// Returns None if the point is not valid (only ~6.25% of all 32-byte strings are valid
    /// encodings, use lizard technique to decode arbitrary data).
    ///
    /// Curve25519 has exactly 2^255 - 19 points.
    /// Ristretto removes the cofactor 8 and maps the points to a subgroup of prime order
    /// 2^252 + 27742317777372353535851937790883648493 (the Elligator mapping takes 253 bits).
    pub fn decode(v: &[u8; 32]) -> Option<Self> {
        CompressedRistretto(*v).decompress().map(Self)
    }
    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(v)
            .ok()?
            .decompress()
            .map(Self)
    }
    /// Encode to a 32-byte array.
    /// Any GroupElement can be encoded this way.
    pub fn encode(&self) -> [u8; 32] {
        self.0.compress().0
    }

    /// Decode a 64-byte hash into a Ristretto point.
    /// This is a one-way function. Multiple hashes can map to the same point.
    pub fn decode_from_hash(v: &[u8; 64]) -> Self {
        Self(RistrettoPoint::from_uniform_bytes(v))
    }

    /// Decode any 16-byte string into a Ristretto point bijectively, using the lizard approach.
    /// There are practically no invalid lizard encodings!
    /// This is useful to encode arbitrary data as group element.
    pub fn decode_lizard(v: &[u8; 16]) -> Self {
        Self(RistrettoPoint::lizard_encode::<Sha256>(v))
    }

    /// Encode to a 16-byte string using the lizard approach.
    /// Notice that a Ristretto point is represented as 32 bytes with ~2^252 valid points, so only
    /// a very small fraction of points (only those decoded from lizard) can be encoded this way.
    pub fn encode_lizard(&self) -> Option<[u8; 16]> {
        self.0.lizard_decode::<Sha256>()
    }

    /// Decode a hexadecimal string into a Ristretto point of 32 bytes or 64 characters.
    /// Returns None if the string is not a valid hexadecimal encoding of a Ristretto point.
    pub fn decode_from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            // A valid hexadecimal string should be 64 characters long for 32 bytes
            return None;
        }
        let bytes = match hex::decode(s) {
            Ok(v) => v,
            Err(_) => return None,
        };
        CompressedRistretto::from_slice(&bytes)
            .unwrap()
            .decompress()
            .map(Self)
    }
    /// Encode to a hexadecimal string.
    pub fn encode_as_hex(&self) -> String {
        hex::encode(self.encode())
    }

    /// Return the identity element of the group.
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }
}

#[cfg(feature = "serde")]
impl Serialize for GroupElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.encode_as_hex().as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for GroupElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GroupElementVisitor;
        impl Visitor<'_> for GroupElementVisitor {
            type Value = GroupElement;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a GroupElement")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                GroupElement::decode_from_hex(v)
                    .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(GroupElementVisitor)
    }
}

impl Hash for GroupElement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}
