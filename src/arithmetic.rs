use base64::Engine;
use base64::engine::general_purpose;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand_core::{CryptoRng, RngCore};

/// Constant so that a [ScalarNonZero]/[ScalarCanBeZero] s can be converted to a [GroupElement] by performing `s * G`.
pub const G: GroupElement = GroupElement(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT);

/// Returned if a zero scalar is inverted (which is similar to why a division by zero is not
/// possible).
#[derive(Debug)]
pub struct ZeroArgumentError;

/// Element on a group. Can not be converted to a scalar. Supports addition and substraction. Multiplication by a scalar is supported.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GroupElement(pub(crate) RistrettoPoint);

impl GroupElement {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(RistrettoPoint::random(rng))
    }
    pub fn decode(v: &[u8; 32]) -> Option<Self> {
        CompressedRistretto(*v).decompress().map(Self)
        // TODO this will fail in specific cases! See https://ristretto.group/test_vectors/ristretto255.html bad_encodings which we include in our tests/arithmetic.rs. We need to create our own bijective encoding (for example, take 30 bytes and add 2 bytes of random padding, proofing that there's always a valid encoding)
    }
    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != 32 {
            None
        } else {
            CompressedRistretto::from_slice(v).unwrap().decompress().map(Self)
        }
    }
    pub fn decode_from_hash(v: &[u8; 64]) -> Self {
        Self(RistrettoPoint::from_uniform_bytes(v))
    }
    pub fn decode_from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 { // A valid hexadecimal string should be 64 characters long for 32 bytes
            return None;
        }
        let bytes = match hex::decode(s) {
            Ok(v) => v,
            Err(_) => return None,
        };
        CompressedRistretto::from_slice(&bytes).unwrap().decompress().map(Self)
    }
    pub fn encode(&self) -> [u8; 32] {
        self.0.compress().0
    }
    pub fn encode_to_hex(&self) -> String {
        hex::encode(self.encode())
    }
    pub fn encode_to_base64(&self) -> String {
        general_purpose::URL_SAFE.encode(&self.encode())
    }
    pub fn decode_from_base64(s: &str) -> Option<Self> {
        general_purpose::URL_SAFE.decode(s).ok().and_then(|v| Self::decode_from_slice(&v))
    }
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }
    pub fn raw(&self) -> &RistrettoPoint {
        &self.0
    }
}

/// Scalar, always non-zero. Can be converted to a GroupElement. Supports multiplication, and inversion (so division is possible). For addition and substraction, use [ScalarCanBeZero].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScalarNonZero(Scalar);

impl ScalarNonZero {
    /// Always return a non-zero scalar.
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

/// Scalar, can be zero. Can be converted to a GroupElement. Supports multiplication, inversion (so division is possible), addition and substraction.
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
        if s.len() != 64 { // A valid hexadecimal string should be 64 characters long for 32 bytes
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

pub trait ScalarTraits {
    fn encode(&self) -> [u8; 32] {
        let mut retval = [0u8; 32];
        retval[0..32].clone_from_slice(self.raw().as_bytes());
        retval
    }
    fn encode_to_hex(&self) -> String {
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

impl<'a, 'b> std::ops::Add<&'b ScalarCanBeZero> for &'a ScalarCanBeZero {
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

impl<'a> std::ops::Add<ScalarCanBeZero> for &'a ScalarCanBeZero {
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

impl<'a, 'b> std::ops::Sub<&'b ScalarCanBeZero> for &'a ScalarCanBeZero {
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

impl<'a> std::ops::Sub<ScalarCanBeZero> for &'a ScalarCanBeZero {
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

impl<'a, 'b> std::ops::Mul<&'b ScalarNonZero> for &'a ScalarNonZero {
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

impl<'a> std::ops::Mul<ScalarNonZero> for &'a ScalarNonZero {
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

impl<'a, 'b> std::ops::Add<&'b GroupElement> for &'a GroupElement {
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

impl<'a> std::ops::Add<GroupElement> for &'a GroupElement {
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

impl<'a, 'b> std::ops::Sub<&'b GroupElement> for &'a GroupElement {
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

impl<'a> std::ops::Sub<GroupElement> for &'a GroupElement {
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

impl<'a, 'b> std::ops::Mul<&'b GroupElement> for &'a ScalarNonZero {
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

impl<'a> std::ops::Mul<GroupElement> for &'a ScalarNonZero {
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

impl<'a, 'b> std::ops::Mul<&'b GroupElement> for &'a ScalarCanBeZero {
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

impl<'a> std::ops::Mul<GroupElement> for &'a ScalarCanBeZero {
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
