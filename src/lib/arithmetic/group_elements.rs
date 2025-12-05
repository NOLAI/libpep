use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::de::{Error, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::fmt::Formatter;
use std::hash::Hash;

/// The base point constant so that a [`ScalarNonZero`](super::ScalarNonZero)/[`ScalarCanBeZero`](super::ScalarCanBeZero) `s` can be converted to a [`GroupElement`] by performing `s * G`.
pub const G: GroupElement = GroupElement(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT);

/// Element on a group.
///
/// Cannot be converted to a scalar. Supports addition and subtraction. Multiplication by a scalar is supported.
/// We use ristretto points to discard unsafe points and safely use the group operations in higher level protocols without any other cryptographic assumptions.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GroupElement(pub(crate) RistrettoPoint);

impl GroupElement {
    /// Generate a random `GroupElement`. This is the preferred way of generating pseudonyms.
    #[must_use]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(RistrettoPoint::random(rng))
    }

    /// Create from a 32-byte compressed Ristretto point.
    ///
    /// Returns `None` if the point is not valid (only ~6.25% of all 32-byte strings are valid
    /// encodings, use lizard technique to decode arbitrary data).
    ///
    /// Curve25519 has exactly 2^255 - 19 points.
    /// Ristretto removes the cofactor 8 and maps the points to a subgroup of prime order
    /// 2^252 + 27742317777372353535851937790883648493 (the Elligator mapping takes 253 bits).
    #[must_use]
    pub fn from_bytes(v: &[u8; 32]) -> Option<Self> {
        CompressedRistretto(*v).decompress().map(Self)
    }

    /// Create from a byte slice.
    #[must_use]
    pub fn from_slice(v: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(v)
            .ok()?
            .decompress()
            .map(Self)
    }

    /// Convert to a 32-byte array.
    ///
    /// Any `GroupElement` can be converted this way.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().0
    }

    /// Create from a 64-byte hash.
    ///
    /// This is a one-way function. Multiple hashes can map to the same point.
    #[must_use]
    pub fn from_hash(v: &[u8; 64]) -> Self {
        Self(RistrettoPoint::from_uniform_bytes(v))
    }

    /// Create from any 16-byte string bijectively, using the lizard approach.
    ///
    /// There are practically no invalid lizard encodings!
    /// This is useful to encode arbitrary data as group element.
    #[must_use]
    pub fn from_lizard(v: &[u8; 16]) -> Self {
        Self(RistrettoPoint::lizard_encode::<Sha256>(v))
    }

    /// Convert to a 16-byte string using the lizard approach.
    ///
    /// Notice that a Ristretto point is represented as 32 bytes with ~2^252 valid points, so only
    /// a very small fraction of points (only those created from lizard) can be converted this way.
    #[must_use]
    pub fn to_lizard(&self) -> Option<[u8; 16]> {
        self.0.lizard_decode::<Sha256>()
    }

    /// Create from a hexadecimal string (32 bytes or 64 characters).
    ///
    /// Returns `None` if the string is not a valid hexadecimal encoding of a Ristretto point.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            // A valid hexadecimal string should be 64 characters long for 32 bytes
            return None;
        }
        let bytes = match hex::decode(s) {
            Ok(v) => v,
            Err(_) => return None,
        };
        // SAFETY: hex::decode of 64 chars produces exactly 32 bytes, so from_slice cannot fail
        #[allow(clippy::unwrap_used)]
        CompressedRistretto::from_slice(&bytes)
            .unwrap()
            .decompress()
            .map(Self)
    }

    /// Convert to a hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Return the identity element of the group.
    #[must_use]
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
        serializer.serialize_str(self.to_hex().as_str())
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
                GroupElement::from_hex(v)
                    .ok_or(E::custom(format!("invalid hex encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(GroupElementVisitor)
    }
}

impl Hash for GroupElement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::scalars::ScalarNonZero;
    use rand_core::RngCore;

    #[test]
    fn encode_decode() {
        let mut rng = rand::rng();
        let original = GroupElement::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = GroupElement::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn serde_json_roundtrip() {
        let mut rng = rand::rng();
        let original = GroupElement::random(&mut rng);
        let json = serde_json::to_string(&original).expect("serialization should succeed");
        let deserialized: GroupElement =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(deserialized, original);
    }

    #[test]
    fn decode_arbitrary_bytes() {
        let bytes = b"test data dsfdsdfsd wefwefew dfd";
        let element = GroupElement::from_bytes(bytes).expect("decoding should succeed");
        let encoded = element.to_bytes();
        assert_eq!(encoded, *bytes);
    }

    #[test]
    fn addition_is_commutative() {
        let mut rng = rand::rng();
        let g = GroupElement::random(&mut rng);
        let h = GroupElement::random(&mut rng);
        assert_eq!(g + h, h + g);
    }

    #[test]
    fn scalar_multiplication_distributes() {
        let mut rng = rand::rng();
        let g = GroupElement::random(&mut rng);
        let h = GroupElement::random(&mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let left = s * (g + h);
        let right = s * g + s * h;
        assert_eq!(left, right);
    }

    #[test]
    fn scalar_identity() {
        let mut rng = rand::rng();
        let g = GroupElement::random(&mut rng);
        let one = ScalarNonZero::one();
        assert_eq!(one * g, g);
    }

    #[test]
    fn lizard_edge_cases() {
        let edge_cases = [
            "00000000000000000000000000000000",
            "00ffffffffffffffffffffffffffffff",
            "f3ffffffffffffffffffffffffffff7f",
            "ffffffffffffffffffffffffffffffff",
            "01ffffffffffffffffffffffffffffff",
            "edffffffffffffffffffffffffffff7f",
            "01000000000000000000000000000000",
            "ecffffffffffffffffffffffffffff7f",
        ];
        for encoding in edge_cases {
            let case = hex::decode(encoding).expect("hex decoding should succeed");
            let bytes = <&[u8; 16]>::try_from(case.as_slice()).expect("should be 16 bytes");
            let element = GroupElement::from_lizard(bytes);
            let encoded = element.to_lizard().expect("lizard encoding should succeed");
            assert_eq!(encoded, *bytes);
        }
    }

    #[test]
    fn lizard_random_roundtrip() {
        let mut rng = rand::rng();
        let mut random_bytes = [0u8; 16];
        rng.fill_bytes(&mut random_bytes);

        let element = GroupElement::from_lizard(&random_bytes);
        let encoded = element.to_lizard().expect("lizard encoding should succeed");
        assert_eq!(encoded, random_bytes);
    }

    #[test]
    fn lizard_fails_after_scalar_multiplication() {
        let mut rng = rand::rng();
        let mut random_bytes = [0u8; 16];
        rng.fill_bytes(&mut random_bytes);

        let element = GroupElement::from_lizard(&random_bytes);
        let s = ScalarNonZero::random(&mut rng);
        let scaled = s * element;

        // After scalar multiplication, element is no longer in lizard form (extremely likely)
        assert!(scaled.to_lizard().is_none());
    }
}
