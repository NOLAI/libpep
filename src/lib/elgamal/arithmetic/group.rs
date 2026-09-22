//! The prime-order group API of [RFC 9497, Section 2.1](https://www.rfc-editor.org/rfc/rfc9497#section-2.1),
//! over which the rest of the library is generic.
//!
//! A [`Group`] is a marker type: it carries no data, and names a ciphersuite (a group together
//! with its scalar type, encodings and hash functions). The library's generic types take it as
//! a type parameter; the `ristretto255` instance is [`Ristretto255`](super::Ristretto255), and
//! the non-generic names at the crate's module level (`Pseudonym`, `SessionKeys`, `Transcryptor`,
//! ...) are aliases that pin it.
//!
//! Beyond the RFC 9497 API, [`Group`] has what the PEP operations need and RFC 9497 does not:
//! a multiplicative identity for identity factors, random elements for pseudonyms, and the
//! mapping of a 64-byte hash to a scalar or an element that factor derivation uses.
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

macro_rules! group_trait {
    ($($extra:tt)*) => {
        /// A prime-order group with its scalar field, serialization and hash-to-group functions.
        ///
        /// See the [module documentation](self) for how it is used. The functions mirror
        /// RFC 9497, Section 2.1; `Scalar` is always non-zero (the library never needs a zero
        /// scalar, and a zero factor would destroy a ciphertext), so the functions that reduce
        /// a hash return `None` where the RFC would return zero.
        pub trait Group: Copy + Clone + Debug + Default + Eq + Hash + Send + Sync + 'static {
            /// A non-zero scalar: an element of the field of integers modulo the group order.
            type Scalar: Copy
                + Eq
                + Debug
                + Send
                + Sync
                + 'static
                + Mul<Self::Scalar, Output = Self::Scalar>
                + Mul<Self::Element, Output = Self::Element>
                $($extra)*;

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

            /// The length of a serialized element in bytes (`Ne` in RFC 9497).
            const NE: usize;
            /// The length of a serialized scalar in bytes (`Ns` in RFC 9497).
            const NS: usize;

            /// The order of the group, as a big-endian integer.
            fn order() -> &'static [u8];

            /// The identity element.
            fn identity() -> Self::Element;

            /// The fixed generator of the group.
            fn generator() -> Self::Element;

            /// `HashToGroup(msg, dst)`: a deterministic map of an arbitrary byte string to a group
            /// element, indifferentiable from a random oracle; RFC 9380 hash-to-curve with domain
            /// separation tag `dst`.
            fn hash_to_group(msg: &[u8], dst: &[u8]) -> Self::Element;

            /// `HashToScalar(msg, dst)`: a deterministic map of an arbitrary byte string to a
            /// scalar, indifferentiable from a random oracle. Returns `None` if the scalar is
            /// zero.
            fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Option<Self::Scalar>;

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
/// Not implemented for any group yet: the padding format, the search for a y-coordinate and
/// the handling of the point's sign are to be specified from the BSNk PP technical specification
/// together with the first Weierstrass-curve group (see the draft's editor's note on the `oaep`
/// encoding).
pub trait OaepEncoding: Group {
    /// The maximum number of payload bytes an element can carry.
    const MAX_LENGTH: usize;

    /// Embed `data` (at most [`MAX_LENGTH`](Self::MAX_LENGTH) bytes) in a group element.
    fn encode_oaep(data: &[u8]) -> Option<Self::Element>;

    /// Recover the payload of an element produced by [`encode_oaep`](Self::encode_oaep).
    fn decode_oaep(element: &Self::Element) -> Option<Vec<u8>>;
}
