//! The data types whose plaintext is a single group element and whose ciphertext is a single
//! ElGamal ciphertext.
//!
//! [`ElGamalEncryptable`] and [`ElGamalEncrypted`] extend the scheme-independent
//! [`Encryptable`] and [`Encrypted`] traits of [`traits`](crate::data::traits) with access to the
//! group element or ciphertext behind a value, and its encodings. Long values and records are
//! built from blocks that implement them; the code that does not look inside a block does not
//! depend on this module.

use crate::data::traits::{Encryptable, Encrypted};
use crate::elgamal::arithmetic::group::{Group, InvertibleEncoding};
use crate::elgamal::ElGamal;
use rand_core::{CryptoRng, Rng};

/// An encrypted type that is a single ElGamal ciphertext, with the encodings of the ciphertext.
pub trait ElGamalEncrypted:
    Encrypted<UnencryptedType: ElGamalEncryptable<EncryptedType = Self, Group = Self::Group>>
{
    /// Get the [ElGamal] ciphertext value.
    fn value(&self) -> &ElGamal<Self::Group>;
    /// Create from an [ElGamal] ciphertext.
    fn from_value(value: ElGamal<Self::Group>) -> Self
    where
        Self: Sized;

    /// Encode as bytes; see [`ElGamal::to_bytes`].
    fn to_bytes(&self) -> Vec<u8> {
        self.value().to_bytes()
    }

    /// Decode from a byte slice; see [`ElGamal::from_slice`].
    fn from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_slice(slice).map(Self::from_value)
    }

    /// Convert to base64 string.
    fn to_base64(&self) -> String {
        self.value().to_base64()
    }

    /// Convert from base64 string.
    fn from_base64(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_base64(s).map(Self::from_value)
    }
}

/// A plaintext type that is a single group element, with the encodings of the element.
///
/// # Access idioms
///
/// Plaintext value types expose their group element through the public `value` field,
/// [`value`](Self::value) and [`from_point`](Self::from_point); *public* key types dereference
/// to their group element; *secret* key material never dereferences and is read only through
/// explicit `value()` calls.
///
/// # Security
///
/// Pseudonym unlinkability assumes that no user knows (or can feasibly find) discrete-log
/// relations between origin identifiers. Origin identifiers are expected to be uniformly random
/// group elements, either sampled directly ([`random`](Self::random)) or produced by the
/// elligator2-based lizard encoding ([`from_lizard`](Self::from_lizard)), both of which rule such
/// relations out. Importing group elements with other distributions via the raw decoders
/// ([`from_bytes`](Self::from_bytes), [`from_hex`](Self::from_hex)) preserves any discrete-log
/// relation between them in every domain (if `M1 = 2*M2`, then `s*M1 = 2*(s*M2)`). Individual
/// pseudonyms remain unlinkable across domains, so this is acceptable as long as no user knows
/// the relations between origin identifiers: a user that does could recognize related pseudonyms
/// by testing for the known relation.
pub trait ElGamalEncryptable: Encryptable {
    /// The group element.
    fn value(&self) -> &<Self::Group as Group>::Element;
    /// Create from a group element.
    fn from_point(value: <Self::Group as Group>::Element) -> Self
    where
        Self: Sized;

    /// Create with a random value.
    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self
    where
        Self: Sized,
    {
        Self::from_point(Self::Group::random_element(rng))
    }
    /// Encode as a byte array of the group's element length (32 bytes on ristretto255).
    fn to_bytes(&self) -> <Self::Group as Group>::ElementBytes {
        Self::Group::serialize_element(self.value())
    }
    /// Convert to a hexadecimal string (64 characters on ristretto255).
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
    /// Create from a byte array of the group's element length.
    /// Returns `None` if the input is not a valid encoding of a group element.
    fn from_bytes(bytes: &<Self::Group as Group>::ElementBytes) -> Option<Self>
    where
        Self: Sized,
    {
        Self::from_slice(bytes.as_ref())
    }
    /// Create from a slice of bytes.
    /// Returns `None` if the input is not a valid encoding of a group element.
    fn from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        Self::Group::deserialize_element(slice).map(Self::from_point)
    }
    /// Create from a hexadecimal string.
    /// Returns `None` if the input is not a valid encoding of a group element.
    fn from_hex(hex: &str) -> Option<Self>
    where
        Self: Sized,
    {
        crate::elgamal::arithmetic::group::decode_hex::<<Self::Group as Group>::ElementBytes>(hex)
            .and_then(|b| Self::from_slice(b.as_ref()))
    }
    /// Create from a 64-byte hash value.
    /// See [`Group::element_from_uniform_bytes`].
    fn from_hash(hash: &[u8; 64]) -> Self
    where
        Self: Sized,
    {
        Self::from_point(Self::Group::element_from_uniform_bytes(hash))
    }
    /// Create from a block of bytes (16 bytes on ristretto255) using the group's invertible
    /// (lizard) encoding.
    /// It accepts any block, so it can create a pseudonym from an existing identifier or encode
    /// an attribute.
    /// See [`InvertibleEncoding::encode_lizard`].
    fn from_lizard(data: &<Self::Group as InvertibleEncoding>::Block) -> Self
    where
        Self: Sized,
        Self::Group: InvertibleEncoding,
    {
        Self::from_point(Self::Group::encode_lizard(data))
    }
    /// Encode as a block of bytes (16 bytes on ristretto255) using the group's invertible
    /// (lizard) encoding.
    /// Returns `None` if the point is not a valid lizard encoding of a block.
    /// See [`InvertibleEncoding::decode_lizard`].
    /// If the value was created using [`ElGamalEncryptable::from_lizard`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    fn to_lizard(&self) -> Option<<Self::Group as InvertibleEncoding>::Block>
    where
        Self::Group: InvertibleEncoding,
    {
        Self::Group::decode_lizard(self.value())
    }
}
