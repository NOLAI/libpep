//! High-level data types for pseudonyms and attributes, and their encrypted versions,
//! Including several ways to encode and decode them.

use crate::internal::arithmetic::GroupElement;
use crate::low_level::elgamal::{ElGamal, ELGAMAL_LENGTH};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A pseudonym (in the background, this is a [`GroupElement`]) that can be used to identify a user
/// within a specific context, which can be encrypted, rekeyed and reshuffled.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct Pseudonym {
    pub value: GroupElement,
}
/// An attribute (in the background, this is a [`GroupElement`]), which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct Attribute {
    pub value: GroupElement,
}
/// An encrypted pseudonym, which is an [`ElGamal`] encryption of a [`Pseudonym`].
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
/// An encrypted attribute, which is an [`ElGamal`] encryption of an [`Attribute`].
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedAttribute {
    pub value: ElGamal,
}

impl Serialize for EncryptedAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedAttribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ElGamal::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

impl Serialize for EncryptedPseudonym {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedPseudonym {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ElGamal::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

/// A trait for encrypted data types, that can be encrypted and decrypted from and into [`Encryptable`] types.
pub trait Encrypted {
    type UnencryptedType: Encryptable;
    /// Get the [ElGamal] ciphertext value.
    fn value(&self) -> &ElGamal;
    /// Create from an [ElGamal] ciphertext.
    fn from_value(value: ElGamal) -> Self
    where
        Self: Sized;
    /// Encode as a byte array.
    fn encode(&self) -> [u8; ELGAMAL_LENGTH] {
        self.value().encode()
    }
    /// Decode from a byte array.
    fn decode(v: &[u8; ELGAMAL_LENGTH]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::decode(v).map(|x| Self::from_value(x))
    }
    /// Decode from a slice of bytes.
    fn decode_from_slice(v: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::decode_from_slice(v).map(|x| Self::from_value(x))
    }
    /// Encode as a base64 string.
    fn as_base64(&self) -> String {
        self.value().encode_as_base64()
    }
    /// Decode from a base64 string.
    /// Returns `None` if the input is not a valid base64 encoding of an [ElGamal] ciphertext.
    fn from_base64(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::decode_from_base64(s).map(|x| Self::from_value(x))
    }
}

/// A trait for encryptable data types, that can be encrypted and decrypted from and into
/// [`Encrypted`] types, and have several ways to encode and decode them.
pub trait Encryptable {
    type EncryptedType: Encrypted;
    fn value(&self) -> &GroupElement;
    fn from_value(value: GroupElement) -> Self
    where
        Self: Sized;

    /// Create from a [`GroupElement`].
    fn from_point(value: GroupElement) -> Self
    where
        Self: Sized,
    {
        Self::from_value(value)
    }

    /// Create with a random value.
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self
    where
        Self: Sized,
    {
        Self::from_point(GroupElement::random(rng))
    }
    /// Encode as a byte array of length 32.
    /// See [`GroupElement::encode`].
    fn encode(&self) -> [u8; 32] {
        self.value().encode()
    }
    /// Encode as a hexadecimal string of 64 characters.
    fn encode_as_hex(&self) -> String {
        self.value().encode_as_hex()
    }
    /// Decode from a byte array of length 32.
    /// Returns `None` if the input is not a valid encoding of a [`GroupElement`].
    /// See [`GroupElement::decode`].
    fn decode(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode(bytes).map(Self::from_point)
    }
    /// Decode from a slice of bytes.
    /// Returns `None` if the input is not a valid encoding of a [`GroupElement`].
    /// See [`GroupElement::decode_from_slice`].
    fn decode_from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_slice(slice).map(Self::from_point)
    }
    /// Decode from a hexadecimal string.
    /// Returns `None` if the input is not a valid encoding of a [`GroupElement`].
    /// See [`GroupElement::decode_from_hex`].
    fn decode_from_hex(hex: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::decode_from_hex(hex).map(Self::from_point)
    }
    /// Create from a hash value.
    /// See [`GroupElement::decode_from_hash`].
    fn from_hash(hash: &[u8; 64]) -> Self
    where
        Self: Sized,
    {
        Self::from_point(GroupElement::decode_from_hash(hash))
    }
    /// Create from a byte array of length 16.
    /// This is useful for creating a pseudonym from an existing identifier or encoding attributes,
    /// as it accepts any 16-byte value.
    /// See [`GroupElement::decode_lizard`].
    fn from_bytes(data: &[u8; 16]) -> Self
    where
        Self: Sized,
    {
        Self::from_point(GroupElement::decode_lizard(data))
    }
    /// Encode as a byte array of length 16.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// See [`GroupElement::encode_lizard`].
    /// If the value was created using [`Encryptable::from_bytes`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    fn as_bytes(&self) -> Option<[u8; 16]> {
        self.value().encode_lizard()
    }
}

impl Encryptable for Pseudonym {
    type EncryptedType = EncryptedPseudonym;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}
impl Encryptable for Attribute {
    type EncryptedType = EncryptedAttribute;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}

/// Trait that associates an encryptable type with its corresponding session key types.
pub trait HasSessionKeys: Encryptable {
    type SessionPublicKey: crate::high_level::keys::PublicKey;
    type SessionSecretKey: crate::high_level::keys::SecretKey;
}

/// Trait that associates an encryptable type with its corresponding global key types.
pub trait HasGlobalKeys: Encryptable {
    type GlobalPublicKey: crate::high_level::keys::PublicKey;
    type GlobalSecretKey: crate::high_level::keys::SecretKey;
}

impl HasSessionKeys for Pseudonym {
    type SessionPublicKey = crate::high_level::keys::PseudonymSessionPublicKey;
    type SessionSecretKey = crate::high_level::keys::PseudonymSessionSecretKey;
}

impl HasSessionKeys for Attribute {
    type SessionPublicKey = crate::high_level::keys::AttributeSessionPublicKey;
    type SessionSecretKey = crate::high_level::keys::AttributeSessionSecretKey;
}

impl HasGlobalKeys for Pseudonym {
    type GlobalPublicKey = crate::high_level::keys::PseudonymGlobalPublicKey;
    type GlobalSecretKey = crate::high_level::keys::PseudonymGlobalSecretKey;
}

impl HasGlobalKeys for Attribute {
    type GlobalPublicKey = crate::high_level::keys::AttributeGlobalPublicKey;
    type GlobalSecretKey = crate::high_level::keys::AttributeGlobalSecretKey;
}

impl Encrypted for EncryptedPseudonym {
    type UnencryptedType = Pseudonym;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}
impl Encrypted for EncryptedAttribute {
    type UnencryptedType = Attribute;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}
