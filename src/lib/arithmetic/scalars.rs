use curve25519_dalek_libpep::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// Returned if a zero scalar is inverted (which is similar to why a division by zero is not possible).
#[derive(Debug)]
pub struct ZeroArgumentError;

/// Scalar, always non-zero.
/// Can be converted to a GroupElement.
/// Supports multiplication, and inversion (so division is possible).
/// For addition and subtraction, use [ScalarCanBeZero].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScalarNonZero(pub(crate) Scalar);

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
pub struct ScalarCanBeZero(pub(crate) Scalar);

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
