//! Core data types for pseudonyms and attributes, their encrypted versions,
//! and session-key based encryption and decryption operations.
//!
//! The types are generic over the [`Group`] in [`generic`]; the names in this module are their
//! ristretto255 instances. The [`ElGamalEncryptable`] and [`ElGamalEncrypted`] traits give
//! access to the single group element or ciphertext behind them, and to its encodings.

pub mod generic;

use crate::data::traits::{Encryptable, Encrypted};
use crate::elgamal::arithmetic::group::{Group, InvertibleEncoding};
use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::Ristretto255;
use crate::elgamal::generic::ElGamal;
use rand_core::{CryptoRng, Rng};

/// The [`Pseudonym`](generic::Pseudonym) over ristretto255.
pub type Pseudonym = generic::Pseudonym<Ristretto255>;
/// The [`Attribute`](generic::Attribute) over ristretto255.
pub type Attribute = generic::Attribute<Ristretto255>;
/// The [`EncryptedPseudonym`](generic::EncryptedPseudonym) over ristretto255.
pub type EncryptedPseudonym = generic::EncryptedPseudonym<Ristretto255>;
/// The [`EncryptedAttribute`](generic::EncryptedAttribute) over ristretto255.
pub type EncryptedAttribute = generic::EncryptedAttribute<Ristretto255>;

impl From<GroupElement> for Pseudonym {
    fn from(value: GroupElement) -> Self {
        Self { value }
    }
}

impl From<GroupElement> for Attribute {
    fn from(value: GroupElement) -> Self {
        Self { value }
    }
}

impl From<crate::elgamal::ElGamal> for EncryptedPseudonym {
    fn from(value: crate::elgamal::ElGamal) -> Self {
        Self { value }
    }
}

impl From<crate::elgamal::ElGamal> for EncryptedAttribute {
    fn from(value: crate::elgamal::ElGamal) -> Self {
        Self { value }
    }
}

/// A marker trait for encrypted types that use ElGamal encryption with a single ciphertext value.
/// This enables access to ElGamal-specific operations like serialization.
pub trait ElGamalEncrypted: Encrypted {
    type UnencryptedType: ElGamalEncryptable<EncryptedType = Self, Group = Self::Group>;

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

/// A marker trait for encryptable types that use ElGamal encryption with a single plaintext value.
/// This enables access to ElGamal-specific operations like serialization and special encodings.
///
/// # Access idioms
///
/// Plaintext value types expose their group element through the public `value` field and
/// [`from_point`](Self::from_point)/[`to_point`-style](Self::value) conversions; *public* key
/// types dereference to their group element; *secret* key material never dereferences and is
/// read only through explicit `value()` calls.
///
/// # Security
///
/// Pseudonym unlinkability assumes that no party knows (or can feasibly find) discrete-log
/// relations between origin identifiers. Origin identifiers are expected to be uniformly random
/// group elements, either sampled directly ([`random`](Self::random)) or produced by the
/// elligator2-based lizard encoding ([`from_lizard`](Self::from_lizard)), both of which rule such
/// relations out. Importing group elements with other distributions via the raw decoders
/// ([`from_bytes`](Self::from_bytes), [`from_hex`](Self::from_hex)) preserves any discrete-log
/// relation between them in every domain (if `M1 = 2*M2`, then `s*M1 = 2*(s*M2)`). Individual
/// pseudonyms remain unlinkable across domains, so this is acceptable as long as no party knows
/// the relations between origin identifiers: a party that does could recognize related pseudonyms
/// by testing for the known relation.
pub trait ElGamalEncryptable: Encryptable {
    /// Get the group element plaintext value.
    fn value(&self) -> &<Self::Group as Group>::Element;
    /// Create from a group element.
    fn from_value(value: <Self::Group as Group>::Element) -> Self
    where
        Self: Sized;

    /// Create from a group element.
    fn from_point(value: <Self::Group as Group>::Element) -> Self
    where
        Self: Sized,
    {
        Self::from_value(value)
    }

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
        crate::keys::traits::decode_hex::<<Self::Group as Group>::ElementBytes>(hex)
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
    /// This is useful for creating a pseudonym from an existing identifier or encoding attributes,
    /// as it accepts any block.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::{decrypt, encrypt};
    use crate::contexts::EncryptionContext;
    use crate::factors::EncryptionSecret;
    use crate::keys::*;

    #[test]
    fn pseudonym_encode_decode() {
        let mut rng = rand::rng();
        let original = Pseudonym::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = Pseudonym::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn attribute_encode_decode() {
        let mut rng = rand::rng();
        let original = Attribute::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = Attribute::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn pseudonym_from_lizard_roundtrip() {
        let data = b"test identifier!";
        let pseudonym = Pseudonym::from_lizard(data);
        let decoded = pseudonym
            .to_lizard()
            .expect("lizard encoding should succeed");
        assert_eq!(decoded, *data);
    }

    #[test]
    fn attribute_from_lizard_roundtrip() {
        let data = b"some attribute!!";
        let attribute = Attribute::from_lizard(data);
        let decoded = attribute
            .to_lizard()
            .expect("lizard encoding should succeed");
        assert_eq!(decoded, *data);
    }

    #[test]
    fn pseudonym_hex_roundtrip() {
        let mut rng = rand::rng();
        let original = Pseudonym::random(&mut rng);
        let hex = original.to_hex();
        let decoded = Pseudonym::from_hex(&hex).expect("hex decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encrypt_decrypt_pseudonym() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

        let original = Pseudonym::random(&mut rng);
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_decrypt_attribute() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_attribute_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_attribute_session_keys(&global_secret, &session, &enc_secret);

        let original = Attribute::random(&mut rng);
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypted_pseudonym_base64_roundtrip() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, _) =
            make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt(&pseudonym, &session_public, &mut rng);
        let base64 = encrypted.to_base64();
        let decoded =
            EncryptedPseudonym::from_base64(&base64).expect("base64 decoding should succeed");

        assert_eq!(decoded, encrypted);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn encrypted_attribute_serde_json() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_attribute_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, _) =
            make_attribute_session_keys(&global_secret, &session, &enc_secret);

        let attribute = Attribute::random(&mut rng);
        let encrypted = encrypt(&attribute, &session_public, &mut rng);
        let json = serde_json::to_string(&encrypted).expect("serialization should succeed");
        let deserialized: EncryptedAttribute =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(deserialized, encrypted);
    }

    #[test]
    fn polymorphic_encrypt_decrypt() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

        let original = Pseudonym::random(&mut rng);
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }
}
