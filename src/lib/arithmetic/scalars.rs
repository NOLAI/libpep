use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// Returned if a zero scalar is inverted (which is similar to why a division by zero is not possible).
#[derive(Debug)]
pub struct ZeroArgumentError;

/// Scalar, always non-zero.
///
/// Can be converted to a [`GroupElement`](super::GroupElement).
/// Supports multiplication, and inversion (so division is possible).
/// For addition and subtraction, use [`ScalarCanBeZero`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScalarNonZero(pub(crate) Scalar);

impl ScalarNonZero {
    /// Always return a random non-zero scalar.
    #[must_use]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let r = ScalarCanBeZero::random(rng);
            if let Ok(s) = r.try_into() {
                return s;
            }
        }
    }

    /// Create from a 32-byte array.
    #[must_use]
    pub fn from_bytes(v: &[u8; 32]) -> Option<Self> {
        ScalarCanBeZero::from_bytes(v).and_then(|x| x.try_into().ok())
    }

    /// Create from a byte slice.
    #[must_use]
    pub fn from_slice(v: &[u8]) -> Option<Self> {
        ScalarCanBeZero::from_slice(v).and_then(|x| x.try_into().ok())
    }

    /// Create from a 64-byte hash.
    #[must_use]
    pub fn from_hash(v: &[u8; 64]) -> Self {
        let retval = Scalar::from_bytes_mod_order_wide(v);
        if retval.as_bytes().iter().all(|x| *x == 0) {
            Self(Scalar::ONE)
        } else {
            Self(retval)
        }
    }

    /// Create from a hexadecimal string.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        ScalarCanBeZero::from_hex(s).and_then(|x| x.try_into().ok())
    }

    /// Return the multiplicative identity (one).
    #[must_use]
    pub fn one() -> Self {
        Self(Scalar::ONE)
    }

    /// Compute the multiplicative inverse.
    #[must_use]
    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
}

/// Scalar, can be zero.
///
/// Can be converted to a [`GroupElement`](super::GroupElement).
/// Supports multiplication, inversion (so division is possible), addition and subtraction.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScalarCanBeZero(pub(crate) Scalar);

impl ScalarCanBeZero {
    /// Generate a random scalar.
    #[must_use]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }

    /// Create from a 32-byte array.
    #[must_use]
    pub fn from_bytes(v: &[u8; 32]) -> Option<Self> {
        Option::from(Scalar::from_canonical_bytes(*v).map(Self))
    }

    /// Create from a byte slice.
    #[must_use]
    pub fn from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != 32 {
            None
        } else {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(v);
            Option::from(Scalar::from_canonical_bytes(tmp).map(Self))
        }
    }

    /// Create from a hexadecimal string.
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
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(&bytes);
        Option::from(Scalar::from_canonical_bytes(tmp).map(Self))
    }

    /// Return the multiplicative identity (one).
    #[must_use]
    pub fn one() -> Self {
        Self(Scalar::ONE)
    }

    /// Return the additive identity (zero).
    #[must_use]
    pub fn zero() -> Self {
        Self(Scalar::ZERO)
    }

    /// Check if this scalar is zero.
    #[must_use]
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
    /// Convert the scalar to a 32-byte array.
    fn to_bytes(&self) -> [u8; 32] {
        let mut retval = [0u8; 32];
        retval[0..32].clone_from_slice(self.raw().as_bytes());
        retval
    }
    /// Convert the scalar to a 32-byte (or 64 character) hexadecimal string.
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_non_zero() {
        let mut rng = rand::rng();
        let original = ScalarNonZero::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = ScalarNonZero::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_decode_can_be_zero() {
        let mut rng = rand::rng();
        let original = ScalarCanBeZero::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = ScalarCanBeZero::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn addition() {
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let b = ScalarNonZero::random(&mut rng);
        let sum = ScalarCanBeZero::from(a) + ScalarCanBeZero::from(b);
        assert_ne!(sum, ScalarCanBeZero::zero()); // Very unlikely to be zero
    }

    #[test]
    fn multiplication() {
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let b = ScalarNonZero::random(&mut rng);
        let product = a * b;
        assert_ne!(product, ScalarNonZero::one()); // Very unlikely to be one
    }

    #[test]
    fn inversion() {
        let mut rng = rand::rng();
        let a = ScalarNonZero::random(&mut rng);
        let inv = a.invert();
        let should_be_one = a * inv;
        assert_eq!(should_be_one, ScalarNonZero::one());
    }
}
