//! High-level data types for pseudonyms and data points, and their encrypted versions,
//! Including several ways to encode and decode them.

use crate::internal::arithmetic::GroupElement;
use crate::low_level::elgamal::{ElGamal, ELGAMAL_LENGTH};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Error, ErrorKind};

/// A pseudonym (in the background, this is a [`GroupElement`]) that can be used to identify a user
/// within a specific context, which can be encrypted, rekeyed and reshuffled.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct Pseudonym {
    pub(crate) value: GroupElement,
}
/// A data point (in the background, this is a [`GroupElement`]), which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct DataPoint {
    pub(crate) value: GroupElement,
}
/// An encrypted pseudonym, which is an [`ElGamal`] encryption of a [`Pseudonym`].
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
/// An encrypted data point, which is an [`ElGamal`] encryption of a [`DataPoint`].
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedDataPoint {
    pub value: ElGamal,
}

impl Serialize for EncryptedDataPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedDataPoint {
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
    const IS_PSEUDONYM: bool = false;
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
    /// This is useful for creating a pseudonym from an existing identifier or encoding data points,
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

    /// Encodes an arbitrary byte array into one or more encryptables
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    fn from_bytes_padded(data: &[u8]) -> Vec<Self>
    where
        Self: Sized,
    {
        if data.is_empty() {
            return vec![];
        }

        let mut result = Vec::new();

        // Process all full blocks, that do not need padding
        // Initialize the last block with the padding value
        // Copy remaining data if there is any
        for i in 0..(data.len() / 16) {
            let start = i * 16;
            // This is safe, as we know that the slice is 16 bytes long
            result.push(Self::from_bytes(
                &data[start..start + 16].try_into().unwrap(),
            ));
        }

        let remaining = data.len() % 16;
        let padding_byte = (16 - remaining) as u8;

        let mut last_block = [padding_byte; 16];

        if remaining > 0 {
            last_block[..remaining].copy_from_slice(&data[data.len() - remaining..]);
        }

        result.push(Self::from_bytes(&last_block));

        result
    }

    /// Encodes an arbitrary string into one or more encryptables
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    fn from_string_padded(text: &str) -> Vec<Self>
    where
        Self: Sized,
    {
        // Convert string to bytes and pass to the byte encoding function
        Self::from_bytes_padded(text.as_bytes())
    }

    /// Decodes encryptables back to the original string
    /// Returns an error if the decoded bytes are not valid UTF-8
    fn to_string_padded(encryptables: &[Self]) -> Result<String, Error>
    where
        Self: Sized,
    {
        let bytes = Self::to_bytes_padded(encryptables)?;
        String::from_utf8(bytes).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    /// Decodes encryptables back to the original byte array
    fn to_bytes_padded(encryptables: &[Self]) -> Result<Vec<u8>, Error>
    where
        Self: Sized,
    {
        if encryptables.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "No encryptables provided",
            ));
        }

        let mut result = Vec::with_capacity(encryptables.len() * 16);

        // Copy over all blocks except the last one
        // Validate padding and copy the data part of the last block
        // Copy over all blocks except the last one
        for data_point in &encryptables[..encryptables.len() - 1] {
            let block = data_point.as_bytes().ok_or(Error::new(
                ErrorKind::InvalidData,
                "Encryptable conversion to bytes failed",
            ))?;
            result.extend_from_slice(&block);
        }

        // This is safe, we know that there is at least one element in the slice
        let last_block = encryptables.last().unwrap().as_bytes().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Last encryptables conversion to bytes failed",
        ))?;

        let padding_byte = last_block[15];

        if padding_byte == 0 || padding_byte > 16 {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid padding"));
        }

        if last_block[16 - padding_byte as usize..]
            .iter()
            .any(|&b| b != padding_byte)
        {
            return Err(Error::new(ErrorKind::InvalidData, "Inconsistent padding"));
        }

        // Add the data part of the last block
        let data_bytes = 16 - padding_byte as usize;
        result.extend_from_slice(&last_block[..data_bytes]);

        Ok(result)
    }

    /// Create multiple messages from a byte array.
    /// TODO: remove this method, as it cannot handle data that is not a multiple of 16 bytes and padding should generally not belong in this library.
    #[deprecated]
    fn bytes_into_multiple_messages(data: &[u8]) -> Vec<Self>
    where
        Self: Sized,
    {
        data.chunks(16)
            .map(|x| Self::from_bytes(x.try_into().unwrap()))
            .collect()
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
impl Encryptable for DataPoint {
    type EncryptedType = EncryptedDataPoint;
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
impl Encrypted for EncryptedPseudonym {
    type UnencryptedType = Pseudonym;
    const IS_PSEUDONYM: bool = true;
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
impl Encrypted for EncryptedDataPoint {
    type UnencryptedType = DataPoint;
    const IS_PSEUDONYM: bool = false;
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
