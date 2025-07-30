//! Implementation of arithmetic operations on Curve25519 with Ristretto, using the
//! `curve25519-dalek` library.
//!
//! We use the [`signalapp/curve25519-dalek`](https://github.com/signalapp/curve25519-dalek)
//! fork of the well-known [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek)
//! crate (which we published as [`curve25519-dalek-libpep`](https://crates.io/crates/curve25519-dalek-libpep)),
//! to use lizard encoding and decoding for [`GroupElement`]s.
//!
//! Scalars can be converted into [`GroupElement`]s by multiplying them with the base point [`G`].
//!
//! We define two types of scalars: [`ScalarNonZero`] and [`ScalarCanBeZero`] to nicely handle edge
//! cases in the rest of the code where a zero scalar is not allowed.
//! Moreover, we overload the arithmetic operators for addition, subtraction, and multiplication,
//! so that the code is more readable and easier to understand, so it matches the notation in the
//! mathematical papers.

use curve25519_dalek_libpep::ristretto::CompressedRistretto;
use curve25519_dalek_libpep::ristretto::RistrettoPoint;
use curve25519_dalek_libpep::scalar::Scalar;
use curve25519_dalek_libpep::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::fmt::Formatter;
use std::hash::Hash;

/// The base point constant so that a [ScalarNonZero]/[ScalarCanBeZero] s can be converted to a [GroupElement] by performing `s * G`.
pub const G: GroupElement =
    GroupElement(curve25519_dalek_libpep::constants::RISTRETTO_BASEPOINT_POINT);

/// Returned if a zero scalar is inverted (which is similar to why a division by zero is not possible).
#[derive(Debug)]
pub struct ZeroArgumentError;

/// Element on a group. Can not be converted to a scalar. Supports addition and subtraction. Multiplication by a scalar is supported.
/// We use ristretto points to discard unsafe points and safely use the group operations in higher level protocols without any other cryptographic assumptions.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GroupElement(RistrettoPoint);

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

impl Serialize for GroupElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.encode_as_hex().as_str())
    }
}

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

/// Scalar, always non-zero.
/// Can be converted to a GroupElement.
/// Supports multiplication, and inversion (so division is possible).
/// For addition and subtraction, use [ScalarCanBeZero].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScalarNonZero(Scalar);

impl ScalarNonZero {
    /// Always return a random non-zero scalar.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let r = ScalarCanBeZero::random(rng);
            if let Ok(s) = r.try_into() {
                return s;
            }
        }
    }
    pub fn decode(v: &[u8; 32]) -> Option<Self> {
        ScalarCanBeZero::decode(v).and_then(|x| x.try_into().ok())
    }
    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        ScalarCanBeZero::decode_from_slice(v).and_then(|x| x.try_into().ok())
    }
    pub fn decode_from_hash(v: &[u8; 64]) -> Self {
        let retval = Scalar::from_bytes_mod_order_wide(v);
        if retval.as_bytes().iter().all(|x| *x == 0) {
            Self(Scalar::ONE)
        } else {
            Self(retval)
        }
    }
    pub fn decode_from_hex(s: &str) -> Option<Self> {
        ScalarCanBeZero::decode_from_hex(s).and_then(|x| x.try_into().ok())
    }
    pub fn one() -> Self {
        Self(Scalar::ONE)
    }

    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
}

/// Scalar, can be zero.
/// Can be converted to a GroupElement.
/// Supports multiplication, inversion (so division is possible), addition and subtraction.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScalarCanBeZero(Scalar);

impl ScalarCanBeZero {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }
    pub fn decode(v: &[u8; 32]) -> Option<Self> {
        Option::from(Scalar::from_canonical_bytes(*v).map(Self))
    }
    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != 32 {
            None
        } else {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(v);
            Option::from(Scalar::from_canonical_bytes(tmp).map(Self))
        }
    }
    pub fn decode_from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            // A valid hexadecimal string should be 64 characters long for 32 bytes
            return None;
        }
        let bytes = match hex::decode(s) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(&bytes);
        Option::from(Scalar::from_canonical_bytes(tmp).map(Self))
    }
    pub fn one() -> Self {
        Self(Scalar::ONE)
    }

    pub fn zero() -> Self {
        Self(Scalar::ZERO)
    }

    pub fn is_zero(&self) -> bool {
        self.0.as_bytes().iter().all(|x| *x == 0)
    }
}

impl From<ScalarNonZero> for ScalarCanBeZero {
    fn from(value: ScalarNonZero) -> Self {
        Self(value.0)
    }
}

impl TryFrom<ScalarCanBeZero> for ScalarNonZero {
    type Error = ZeroArgumentError;

    fn try_from(value: ScalarCanBeZero) -> Result<Self, Self::Error> {
        if value.is_zero() {
            Err(ZeroArgumentError)
        } else {
            Ok(Self(value.0))
        }
    }
}

/// Trait for encoding of scalars.
///
/// Since scalars are typically secret values, we do not implement a way to serialize them, and
/// encoding methods are not public.
pub trait ScalarTraits {
    /// Encode the scalar to a 32-byte array.
    fn encode(&self) -> [u8; 32] {
        let mut retval = [0u8; 32];
        retval[0..32].clone_from_slice(self.raw().as_bytes());
        retval
    }
    /// Encode the scalar to a 32-byte (or 64 character) hexadecimal string.
    fn encode_as_hex(&self) -> String {
        hex::encode(self.encode())
    }
    fn raw(&self) -> &Scalar;
}

impl ScalarTraits for ScalarCanBeZero {
    fn raw(&self) -> &Scalar {
        &self.0
    }
}

impl ScalarTraits for ScalarNonZero {
    fn raw(&self) -> &Scalar {
        &self.0
    }
}

impl<'b> std::ops::Add<&'b ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        ScalarCanBeZero(self.0 + rhs.0)
    }
}

impl<'b> std::ops::Add<&'b ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(mut self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl std::ops::Add<ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(self, mut rhs: ScalarCanBeZero) -> Self::Output {
        rhs.0 += self.0;
        rhs
    }
}

impl std::ops::Add<ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(mut self, rhs: ScalarCanBeZero) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl<'b> std::ops::Sub<&'b ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        ScalarCanBeZero(self.0 - rhs.0)
    }
}

impl<'b> std::ops::Sub<&'b ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(mut self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl std::ops::Sub<ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(self, rhs: ScalarCanBeZero) -> Self::Output {
        ScalarCanBeZero(self.0 - rhs.0)
    }
}

impl std::ops::Sub<ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl<'b> std::ops::Mul<&'b ScalarNonZero> for &ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(self, rhs: &'b ScalarNonZero) -> Self::Output {
        ScalarNonZero(self.0 * rhs.0)
    }
}

impl<'b> std::ops::Mul<&'b ScalarNonZero> for ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(mut self, rhs: &'b ScalarNonZero) -> Self::Output {
        self.0 *= rhs.0;
        self
    }
}

impl std::ops::Mul<ScalarNonZero> for &ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(self, mut rhs: ScalarNonZero) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl std::ops::Mul<ScalarNonZero> for ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self.0 *= rhs.0;
        self
    }
}

impl<'b> std::ops::Add<&'b GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn add(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 + rhs.0)
    }
}

impl<'b> std::ops::Add<&'b GroupElement> for GroupElement {
    type Output = GroupElement;

    fn add(mut self, rhs: &'b GroupElement) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl std::ops::Add<GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn add(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 += self.0;
        rhs
    }
}

impl std::ops::Add<GroupElement> for GroupElement {
    type Output = GroupElement;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl<'b> std::ops::Sub<&'b GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn sub(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 - rhs.0)
    }
}

impl<'b> std::ops::Sub<&'b GroupElement> for GroupElement {
    type Output = GroupElement;

    fn sub(mut self, rhs: &'b GroupElement) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl std::ops::Sub<GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn sub(self, rhs: GroupElement) -> Self::Output {
        GroupElement(self.0 - rhs.0)
    }
}

impl std::ops::Sub<GroupElement> for GroupElement {
    type Output = GroupElement;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for &ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl std::ops::Mul<GroupElement> for &ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl std::ops::Mul<GroupElement> for ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for &ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl std::ops::Mul<GroupElement> for &ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl std::ops::Mul<GroupElement> for ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}
