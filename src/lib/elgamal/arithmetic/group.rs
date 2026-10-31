//! The prime-order group API over which the data types of the library are generic.
//!
//! A [`Group`] is a marker type: it carries no data, and names a prime-order group together with
//! its scalar type and encodings. The data types take it as a type parameter (`Pseudonym<G>`,
//! `SessionKeys<G>`, ...), instantiated with [`Ristretto255`](super::Ristretto255). Hashing is not
//! part of the group: the functions and types that hash are generic over a
//! [`Ciphersuite`](super::Ciphersuite), which pairs a group with a hash.
//!
//! Beyond a bare prime-order group API, [`Group`] has what the PEP operations need:
//! a multiplicative identity for identity factors, random elements for pseudonyms, and the
//! mapping of 64 uniform bytes to a scalar or an element that the ciphersuites hash into.
//!
//! # Element encodings
//!
//! How an identifier or a payload is turned into an element is not part of the group API but
//! of the deployment. Two named encodings exist as optional traits: [`InvertibleEncoding`]
//! (the lizard encoding, ristretto255 only) and [`OaepEncoding`] (an x-coordinate embedding for
//! Weierstrass curves, to be implemented). Every encoding MUST be such that nobody can produce
//! two encoded inputs with a known discrete-log relation: reshuffling is linear, so a relation
//! `M2 = a * M1` between origin identifiers survives in every pseudonymization domain. Encoding
//! an identifier `x` as `x * G` is therefore forbidden.

use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Add, Mul, Sub};

/// A fixed-size byte string, as returned by the serialization functions of a [`Group`].
///
/// Implemented for every `[u8; N]`.
pub trait Bytes:
    AsRef<[u8]> + AsMut<[u8]> + Copy + Eq + Hash + Debug + Send + Sync + 'static
{
    /// The all-zero byte string of this length.
    fn zeroed() -> Self;
    /// The length in bytes.
    fn len() -> usize;
}

impl<const N: usize> Bytes for [u8; N] {
    fn zeroed() -> Self {
        [0; N]
    }
    fn len() -> usize {
        N
    }
}

/// Decode a hexadecimal string of exactly the length of `B`.
pub(crate) fn decode_hex<B: Bytes>(s: &str) -> Option<B> {
    if s.len() != 2 * B::len() {
        return None;
    }
    let mut out = B::zeroed();
    hex::decode_to_slice(s, out.as_mut()).ok()?;
    Some(out)
}

macro_rules! group_trait {
    ($($extra:tt)*) => {
        /// A prime-order group with its scalar field and serialization.
        ///
        /// See the [module documentation](self) for how it is used. `Scalar` is always non-zero (the library never needs a zero
        /// scalar, and a zero factor would destroy a ciphertext), so the functions that reduce
        /// a hash return `None` where a plain group API would return zero.
        pub trait Group: Copy + Clone + Debug + Default + Eq + Hash + Send + Sync + 'static {
            /// A non-zero scalar: an element of the field of integers modulo the group order.
            type Scalar: Copy
                + Eq
                + Debug
                + Send
                + Sync
                + zeroize::Zeroize
                + 'static
                + Mul<Self::Scalar, Output = Self::Scalar>
                + Mul<Self::Element, Output = Self::Element>
                + TryFrom<Self::ScalarCanBeZero>
                $($extra)*;

            /// A scalar that may be zero: an element of the scalar field with its addition, for
            /// the challenges and responses of zero-knowledge proofs, which are sums. The
            /// default value is zero.
            type ScalarCanBeZero: Copy
                + Eq
                + Debug
                + Default
                + Send
                + Sync
                + 'static
                + Add<Self::ScalarCanBeZero, Output = Self::ScalarCanBeZero>
                + Sub<Self::ScalarCanBeZero, Output = Self::ScalarCanBeZero>
                + Mul<Self::ScalarCanBeZero, Output = Self::ScalarCanBeZero>
                + Mul<Self::Element, Output = Self::Element>
                + From<Self::Scalar>;

            /// A group element.
            type Element: Copy
                + Eq
                + Hash
                + Debug
                + Send
                + Sync
                + 'static
                + Add<Self::Element, Output = Self::Element>
                + Sub<Self::Element, Output = Self::Element>
                $($extra)*;

            /// The serialized form of an element: `NE` bytes.
            type ElementBytes: Bytes;
            /// The serialized form of a scalar: `NS` bytes.
            type ScalarBytes: Bytes;

            /// The length of a serialized element in bytes (`Ne`).
            const NE: usize;
            /// The length of a serialized scalar in bytes (`Ns`).
            const NS: usize;

            /// The order of the group, as a big-endian integer.
            fn order() -> &'static [u8];

            /// The identity element.
            fn identity() -> Self::Element;

            /// The fixed generator of the group.
            fn generator() -> Self::Element;

            /// Map 64 uniformly random bytes to a group element. Not invertible.
            fn element_from_uniform_bytes(bytes: &[u8; 64]) -> Self::Element;

            /// Reduce 64 uniformly random bytes modulo the group order. Returns `None` if the
            /// result is zero.
            fn scalar_from_uniform_bytes(bytes: &[u8; 64]) -> Option<Self::Scalar>;

            /// A uniformly random non-zero scalar.
            fn random_scalar<R: Rng + CryptoRng>(rng: &mut R) -> Self::Scalar;

            /// A uniformly random group element.
            fn random_element<R: Rng + CryptoRng>(rng: &mut R) -> Self::Element;

            /// The multiplicative identity of the scalar field.
            fn scalar_one() -> Self::Scalar;

            /// The multiplicative inverse of a scalar.
            fn scalar_inverse(scalar: &Self::Scalar) -> Self::Scalar;

            /// `SerializeElement`: the canonical `NE`-byte encoding of an element.
            fn serialize_element(element: &Self::Element) -> Self::ElementBytes;

            /// `DeserializeElement`: decode an element, rejecting anything that is not a
            /// canonical encoding of a group element, and rejecting the identity element.
            fn deserialize_element(bytes: &[u8]) -> Option<Self::Element>;

            /// `SerializeScalar`: the canonical `NS`-byte encoding of a scalar.
            fn serialize_scalar(scalar: &Self::Scalar) -> Self::ScalarBytes;

            /// `DeserializeScalar`: decode a scalar, rejecting non-canonical encodings and zero.
            fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar>;

            /// The canonical `NS`-byte encoding of a scalar that may be zero.
            fn serialize_scalar_can_be_zero(scalar: &Self::ScalarCanBeZero) -> Self::ScalarBytes;

            /// Decode a scalar that may be zero, rejecting non-canonical encodings.
            fn deserialize_scalar_can_be_zero(bytes: &[u8]) -> Option<Self::ScalarCanBeZero>;

            /// `ScalarMultGen`: multiply the generator by a scalar.
            fn scalar_mult_gen(scalar: &Self::Scalar) -> Self::Element;
        }
    };
}

#[cfg(feature = "serde")]
group_trait!(+ Serialize + DeserializeOwned);
#[cfg(not(feature = "serde"))]
group_trait!();

/// An invertible encoding of fixed-size byte blocks as group elements (the *lizard* encoding
/// on ristretto255).
///
/// Every block encodes to an element, and an element that was produced by [`encode_lizard`]
/// decodes back to the block. An element that was not (a random element, a reshuffled one)
/// fails to decode with overwhelming probability.
///
/// [`encode_lizard`]: InvertibleEncoding::encode_lizard
pub trait InvertibleEncoding: Group {
    /// A block of plaintext bytes.
    type Block: Bytes;

    /// The number of bytes in a block.
    const BLOCK_LENGTH: usize;

    /// Encode a block as a group element.
    fn encode_lizard(block: &Self::Block) -> Self::Element;

    /// Decode a group element produced by [`encode_lizard`](Self::encode_lizard).
    fn decode_lizard(element: &Self::Element) -> Option<Self::Block>;
}

/// An OAEP-style embedding of byte strings in the x-coordinate of a point on a Weierstrass
/// curve, in the manner of the Dutch BSNk pseudonymization scheme on brainpoolP320r1.
///
/// The padding format, the search for a y-coordinate and the handling of the point's sign follow
/// the BSNk PP technical specification.
pub trait OaepEncoding: Group {
    /// The maximum number of payload bytes an element can carry.
    const MAX_LENGTH: usize;

    /// Embed `data` (at most [`MAX_LENGTH`](Self::MAX_LENGTH) bytes) in a group element.
    fn encode_oaep(data: &[u8]) -> Option<Self::Element>;

    /// Recover the payload of an element produced by [`encode_oaep`](Self::encode_oaep).
    fn decode_oaep(element: &Self::Element) -> Option<Vec<u8>>;
}
