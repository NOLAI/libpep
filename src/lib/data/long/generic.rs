//! Long (multi-block) data types for pseudonyms and attributes, generic over the [`Group`].
//!
//! Encoding and padding need the group's [`InvertibleEncoding`]; encryption and transcryption
//! work over any [`Group`].
//!
//! # Padding
//!
//! Long data types use PKCS#7 padding (internal padding) automatically for the last block.
//! They also support optional external padding via the `pad_to()` method for batch unlinkability.
//!
//! For detailed information about the two types of padding, see the [`padding`](crate::data::padding) module.

use crate::data::long::{LongEncryptable, LongEncrypted};
use crate::data::padding::external::{create_external_padding_block, is_external_padding_block};
use crate::data::padding::internal::unpad_block;
use crate::data::simple::generic::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::data::simple::{ElGamalEncryptable, ElGamalEncrypted};
#[cfg(feature = "batch")]
use crate::data::traits::BatchEncryptable;
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::{Bytes, Group, InvertibleEncoding};
use crate::factors::types::generic::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
    TranscryptionInfo,
};
#[cfg(feature = "offline")]
use crate::keys::types::generic::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
use crate::keys::types::generic::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Error, ErrorKind};

#[cfg(feature = "batch")]
use crate::errors::BatchError;
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::generic::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};

/// A collection of [Pseudonym]s that together represent a larger pseudonym value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// **The length (number of blocks) of a `LongPseudonym` may reveal information about the original data!**
///
/// When using `LongPseudonym`:
/// - The number of blocks is visible and may leak information about the data size
/// - Consider padding your data to a fixed size before encoding to prevent length-based
///   information leakage
/// - Pseudonyms with the same prefix or suffix blocks can be linked, as they are
///   similarly reshuffled during pseudonymization
///
/// # Example
///
/// ```no_run
/// use libpep::data::long::LongPseudonym;
///
/// let long_pseudo = LongPseudonym::from_string_padded("some-long-identifier1@example.com");
/// ```
///
/// Notice that in this example, the first 16-byte block will be "some-identifier1" and the second block
/// will be "@example.com" followed by padding bytes. Consequently, even after reshuffling,
/// any other email address ending with "@example.com" will share the same last block and thus
/// can be linked together.
///
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongPseudonym<G: Group>(pub Vec<Pseudonym<G>>);

/// A collection of [Attribute]s that together represent a larger data value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// **The length (number of blocks) of a `LongAttribute` may reveal information about the original data!**
///
/// When using `LongAttribute`:
/// - The number of blocks is visible and may leak information about the data size
/// - Attributes with the same prefix or suffix blocks can be linked together, as they are
///   similarly reshuffled during pseudonymization
/// - Consider padding your data to a fixed size before encoding to prevent length-based
///   information leakage
///
/// # Example
///
/// ```no_run
/// use libpep::data::long::LongAttribute;
///
/// // This will use the minimum number of blocks needed (may leak length information)
/// let long_attr = LongAttribute::from_string_padded("some long and sensitive data");
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongAttribute<G: Group>(pub Vec<Attribute<G>>);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedPseudonym<G: Group>(pub Vec<EncryptedPseudonym<G>>);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedAttribute<G: Group>(pub Vec<EncryptedAttribute<G>>);

impl<G: InvertibleEncoding> LongPseudonym<G> {
    /// Encodes an arbitrary byte array into a `LongPseudonym` using PKCS#7 padding.
    ///
    /// This method never fails and can encode any byte array of any length.
    ///
    /// # Privacy Warning
    ///
    /// The number of blocks will vary with input size, potentially leaking information
    /// about the data length. Consider padding your data to a fixed size before encoding.
    ///
    /// # Parameters
    ///
    /// - `data`: The bytes to encode
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::long::LongPseudonym;
    ///
    /// let long_pseudo = LongPseudonym::from_bytes_padded(b"participant123456789@abcdef.hij");
    /// ```
    pub fn from_bytes_padded(data: &[u8]) -> Self {
        LongPseudonym(from_bytes_padded_impl::<Pseudonym<G>>(data))
    }

    /// Encodes a string into a `LongPseudonym` using PKCS#7 padding.
    ///
    /// This method never fails and can encode any string of any length.
    ///
    /// # Privacy Warning
    ///
    /// The number of blocks will vary with input size, potentially leaking information
    /// about the data length. Consider padding your data to a fixed size before encoding.
    ///
    /// # Parameters
    ///
    /// - `text`: The string to encode
    pub fn from_string_padded(text: &str) -> Self {
        Self::from_bytes_padded(text.as_bytes())
    }

    /// Decodes a `LongPseudonym` back to the original string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `LongPseudonym` is empty
    /// - The padding is invalid
    /// - The decoded bytes are not valid UTF-8
    pub fn to_string_padded(&self) -> Result<String, Error> {
        let bytes = self.to_bytes_padded()?;
        String::from_utf8(bytes).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    /// Decodes a `LongPseudonym` back to the original byte array.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `LongPseudonym` is empty
    /// - The padding is invalid
    pub fn to_bytes_padded(&self) -> Result<Vec<u8>, Error> {
        to_bytes_padded_impl(&self.0)
    }

    /// Convert to a hexadecimal string representation.
    ///
    /// This is useful for displaying pseudonyms that may not be valid UTF-8,
    /// such as those that have been transcrypted across different domains.
    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|pseudonym| pseudonym.to_hex())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Adds **external padding** to reach a target number of blocks for batch unlinkability.
    ///
    /// ## Purpose: Batch Transcryption Unlinkability
    ///
    /// In batch transcryption, all values **must have identical structure** to prevent
    /// linkability attacks. This method adds full padding blocks (external padding) to
    /// normalize different-sized pseudonyms to the same structure without modifying content.
    ///
    /// ## How it Works
    ///
    /// - Appends one or more **all-zero external padding blocks** after the data blocks:
    ///   `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`
    /// - These blocks are **separate from** the internal PKCS#7 padding within blocks
    /// - During decoding, scans backwards removing all-zero blocks until finding the data
    /// - The original pseudonym value is perfectly preserved
    ///
    /// ## Parameters
    ///
    /// - `target_blocks`: The desired number of blocks (must be >= current block count)
    ///
    /// ## Returns
    ///
    /// Returns a new `LongPseudonym` padded to the target number of blocks.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The current number of blocks exceeds the target
    ///
    /// ## Example: Normalizing for Batch Processing
    ///
    /// ```no_run
    /// use libpep::data::long::LongPseudonym;
    ///
    /// let short_pseudo = LongPseudonym::from_string_padded("user123");  // 1 block
    /// let long_pseudo = LongPseudonym::from_string_padded("user@example.com");  // 2 blocks
    ///
    /// // Normalize both to 2 blocks for unlinkable batch transcryption
    /// let short_padded = short_pseudo.pad_to(2).unwrap();
    /// let long_padded = long_pseudo.pad_to(2).unwrap();
    ///
    /// // Both now have identical structure (2 blocks)
    /// assert_eq!(short_padded.len(), 2);
    /// assert_eq!(long_padded.len(), 2);
    ///
    /// // Original values are preserved when decoded
    /// assert_eq!(short_padded.to_string_padded().unwrap(), "user123");
    /// assert_eq!(long_padded.to_string_padded().unwrap(), "user@example.com");
    /// ```
    pub fn pad_to(&self, target_blocks: usize) -> Result<Self, Error> {
        let current_blocks = self.0.len();

        if current_blocks > target_blocks {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Cannot pad: current blocks ({}) exceeds target ({})",
                    current_blocks, target_blocks
                ),
            ));
        }

        if current_blocks == target_blocks {
            return Ok(self.clone());
        }

        // Create external padding blocks (all zeros)
        let padding_pattern = create_external_padding_block::<G::Block>();
        let padding_block = Pseudonym::from_lizard(&padding_pattern);

        let mut blocks = self.0.clone();
        blocks.resize(target_blocks, padding_block);

        Ok(LongPseudonym(blocks))
    }
}

impl<G: InvertibleEncoding> LongAttribute<G> {
    /// Encodes an arbitrary byte array into a `LongAttribute` using PKCS#7 padding.
    ///
    /// This method never fails and can encode any byte array of any length.
    ///
    /// # Privacy Warning
    ///
    /// The number of blocks will vary with input size, potentially leaking information
    /// about the data length. Consider padding your data to a fixed size before encoding.
    ///
    /// # Parameters
    ///
    /// - `data`: The bytes to encode
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::long::LongAttribute;
    ///
    /// let long_attr = LongAttribute::from_bytes_padded(b"some long and sensitive data");
    /// ```
    pub fn from_bytes_padded(data: &[u8]) -> Self {
        LongAttribute(from_bytes_padded_impl::<Attribute<G>>(data))
    }

    /// Encodes a string into a `LongAttribute` using PKCS#7 padding.
    ///
    /// This method never fails and can encode any string of any length.
    ///
    /// # Privacy Warning
    ///
    /// The number of blocks will vary with input size, potentially leaking information
    /// about the data length. Consider padding your data to a fixed size before encoding.
    ///
    /// # Parameters
    ///
    /// - `text`: The string to encode
    pub fn from_string_padded(text: &str) -> Self {
        Self::from_bytes_padded(text.as_bytes())
    }

    /// Decodes a `LongAttribute` back to the original string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `LongAttribute` is empty
    /// - The padding is invalid
    /// - The decoded bytes are not valid UTF-8
    pub fn to_string_padded(&self) -> Result<String, Error> {
        let bytes = self.to_bytes_padded()?;
        String::from_utf8(bytes).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    /// Decodes a `LongAttribute` back to the original byte array.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `LongAttribute` is empty
    /// - The padding is invalid
    pub fn to_bytes_padded(&self) -> Result<Vec<u8>, Error> {
        to_bytes_padded_impl(&self.0)
    }

    /// Convert to a hexadecimal string representation.
    ///
    /// This is useful for displaying attributes that may not be valid UTF-8.
    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|attribute| attribute.to_hex())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Pads this `LongAttribute` to a target number of blocks.
    ///
    /// This is useful for batch operations where all attributes must have the same structure.
    /// Additional padding blocks are all-zero blocks:
    /// `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`
    /// which are automatically detected and removed during decoding.
    ///
    /// # Parameters
    ///
    /// - `target_blocks`: The desired number of blocks (must be >= current block count)
    ///
    /// # Returns
    ///
    /// Returns a new `LongAttribute` padded to the target number of blocks.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The current number of blocks exceeds the target
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::long::LongAttribute;
    ///
    /// let attr = LongAttribute::from_string_padded("hello");
    /// // Pad to 3 blocks for batch processing
    /// let padded = attr.pad_to(3).unwrap();
    /// assert_eq!(padded.len(), 3);
    /// // Decoding still returns the original string
    /// assert_eq!(padded.to_string_padded().unwrap(), "hello");
    /// ```
    pub fn pad_to(&self, target_blocks: usize) -> Result<Self, Error> {
        let current_blocks = self.0.len();

        if current_blocks > target_blocks {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Cannot pad: current blocks ({}) exceeds target ({})",
                    current_blocks, target_blocks
                ),
            ));
        }

        if current_blocks == target_blocks {
            return Ok(self.clone());
        }

        // Create external padding blocks (all zeros)
        let padding_pattern = create_external_padding_block::<G::Block>();
        let padding_block = Attribute::from_lizard(&padding_pattern);

        let mut blocks = self.0.clone();
        blocks.resize(target_blocks, padding_block);

        Ok(LongAttribute(blocks))
    }
}

impl<G: Group> LongEncryptedPseudonym<G> {
    /// Serializes a `LongEncryptedPseudonym` to a string by concatenating the base64-encoded
    /// individual `EncryptedPseudonym` items with "|" as a delimiter.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::long::LongEncryptedPseudonym;
    ///
    /// let long_enc_pseudo = LongEncryptedPseudonym(vec![/* ... */]);
    /// let serialized = long_enc_pseudo.serialize();
    /// ```
    pub fn serialize(&self) -> String {
        self.0
            .iter()
            .map(|item| item.to_base64())
            .collect::<Vec<_>>()
            .join("|")
    }

    /// Deserializes a `LongEncryptedPseudonym` from a string by splitting on "|" and
    /// decoding each base64-encoded `EncryptedPseudonym`.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the base64-encoded parts cannot be decoded.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::long::LongEncryptedPseudonym;
    ///
    /// let serialized = "base64_1|base64_2|base64_3";
    /// let long_enc_pseudo = LongEncryptedPseudonym::deserialize(serialized).unwrap();
    ///
    /// // Empty string deserializes to empty vector
    /// let empty = LongEncryptedPseudonym::deserialize("").unwrap();
    /// assert_eq!(empty.0.len(), 0);
    /// ```
    pub fn deserialize(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Ok(LongEncryptedPseudonym(vec![]));
        }

        let items: Result<Vec<EncryptedPseudonym<G>>, Error> = s
            .split('|')
            .map(|part| {
                EncryptedPseudonym::from_base64(part).ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("Invalid base64 encoding: {}", part),
                    )
                })
            })
            .collect();

        items.map(LongEncryptedPseudonym)
    }
}

impl<G: Group> LongEncryptedAttribute<G> {
    /// Serializes a `LongEncryptedAttribute` to a string by concatenating the base64-encoded
    /// individual `EncryptedAttribute` items with "|" as a delimiter.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::long::LongEncryptedAttribute;
    ///
    /// let long_enc_attr = LongEncryptedAttribute(vec![/* ... */]);
    /// let serialized = long_enc_attr.serialize();
    /// ```
    pub fn serialize(&self) -> String {
        self.0
            .iter()
            .map(|item| item.to_base64())
            .collect::<Vec<_>>()
            .join("|")
    }

    /// Deserializes a `LongEncryptedAttribute` from a string by splitting on "|" and
    /// decoding each base64-encoded `EncryptedAttribute`.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the base64-encoded parts cannot be decoded.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::long::LongEncryptedAttribute;
    ///
    /// let serialized = "base64_1|base64_2|base64_3";
    /// let long_enc_attr = LongEncryptedAttribute::deserialize(serialized).unwrap();
    ///
    /// // Empty string deserializes to empty vector
    /// let empty = LongEncryptedAttribute::deserialize("").unwrap();
    /// assert_eq!(empty.0.len(), 0);
    /// ```
    pub fn deserialize(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Ok(LongEncryptedAttribute(vec![]));
        }

        let items: Result<Vec<EncryptedAttribute<G>>, Error> = s
            .split('|')
            .map(|part| {
                EncryptedAttribute::from_base64(part).ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("Invalid base64 encoding: {}", part),
                    )
                })
            })
            .collect();

        items.map(LongEncryptedAttribute)
    }
}

#[cfg(feature = "serde")]
impl<G: Group> Serialize for LongEncryptedPseudonym<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group> Deserialize<'de> for LongEncryptedPseudonym<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<G: Group> Serialize for LongEncryptedAttribute<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group> Deserialize<'de> for LongEncryptedAttribute<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
    }
}

impl<G: Group> LongEncryptable for LongPseudonym<G> {
    type EncryptedType = LongEncryptedPseudonym<G>;
    type Block = Pseudonym<G>;

    fn blocks(&self) -> &[Self::Block] {
        &self.0
    }

    fn from_encrypted_blocks(
        blocks: Vec<<Self::Block as Encryptable>::EncryptedType>,
    ) -> Self::EncryptedType {
        LongEncryptedPseudonym(blocks)
    }
}

// Implement Encryptable for LongPseudonym
// Uses the same key type as Pseudonym (PseudonymSessionPublicKey)
impl<G: Group> Encryptable for LongPseudonym<G> {
    type Group = G;
    type EncryptedType = LongEncryptedPseudonym<G>;
    type PublicKeyType = PseudonymSessionPublicKey<G>;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = PseudonymGlobalPublicKey<G>;

    fn encrypt<R>(&self, public_key: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        let encrypted_blocks = self
            .blocks()
            .iter()
            .map(|block| block.encrypt(public_key, rng))
            .collect();
        LongEncryptedPseudonym(encrypted_blocks)
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        let encrypted_blocks = self
            .blocks()
            .iter()
            .map(|block| block.encrypt_global(public_key, rng))
            .collect();
        LongEncryptedPseudonym(encrypted_blocks)
    }
}

impl<G: Group> LongEncryptable for LongAttribute<G> {
    type EncryptedType = LongEncryptedAttribute<G>;
    type Block = Attribute<G>;

    fn blocks(&self) -> &[Self::Block] {
        &self.0
    }

    fn from_encrypted_blocks(
        blocks: Vec<<Self::Block as Encryptable>::EncryptedType>,
    ) -> Self::EncryptedType {
        LongEncryptedAttribute(blocks)
    }
}

// Implement Encryptable for LongAttribute
// Uses the same key type as Attribute (AttributeSessionPublicKey)
impl<G: Group> Encryptable for LongAttribute<G> {
    type Group = G;
    type EncryptedType = LongEncryptedAttribute<G>;
    type PublicKeyType = AttributeSessionPublicKey<G>;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = AttributeGlobalPublicKey<G>;

    fn encrypt<R>(&self, public_key: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        let encrypted_blocks = self
            .blocks()
            .iter()
            .map(|block| block.encrypt(public_key, rng))
            .collect();
        LongEncryptedAttribute(encrypted_blocks)
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: Rng + CryptoRng,
    {
        let encrypted_blocks = self
            .blocks()
            .iter()
            .map(|block| block.encrypt_global(public_key, rng))
            .collect();
        LongEncryptedAttribute(encrypted_blocks)
    }
}

impl<G: Group> LongEncrypted for LongEncryptedPseudonym<G> {
    type UnencryptedType = LongPseudonym<G>;
    type EncryptedBlock = EncryptedPseudonym<G>;

    fn encrypted_blocks(&self) -> &[Self::EncryptedBlock] {
        &self.0
    }

    fn from_decrypted_blocks(
        blocks: Vec<<Self::EncryptedBlock as Encrypted>::UnencryptedType>,
    ) -> Self::UnencryptedType {
        LongPseudonym(blocks)
    }

    fn from_encrypted_blocks(blocks: Vec<Self::EncryptedBlock>) -> Self {
        LongEncryptedPseudonym(blocks)
    }
}

impl<G: Group> LongEncrypted for LongEncryptedAttribute<G> {
    type UnencryptedType = LongAttribute<G>;
    type EncryptedBlock = EncryptedAttribute<G>;

    fn encrypted_blocks(&self) -> &[Self::EncryptedBlock] {
        &self.0
    }

    fn from_decrypted_blocks(
        blocks: Vec<<Self::EncryptedBlock as Encrypted>::UnencryptedType>,
    ) -> Self::UnencryptedType {
        LongAttribute(blocks)
    }

    fn from_encrypted_blocks(blocks: Vec<Self::EncryptedBlock>) -> Self {
        LongEncryptedAttribute(blocks)
    }
}

// Implement Encrypted for LongEncryptedPseudonym
impl<G: Group> Encrypted for LongEncryptedPseudonym<G> {
    type Group = G;
    type UnencryptedType = LongPseudonym<G>;
    type SecretKeyType = PseudonymSessionSecretKey<G>;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = PseudonymGlobalSecretKey<G>;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        let decrypted_blocks: Option<Vec<_>> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt(secret_key))
            .collect();
        decrypted_blocks.map(LongPseudonym)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Self::UnencryptedType {
        let decrypted_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt(secret_key))
            .collect();
        LongPseudonym(decrypted_blocks)
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        let decrypted_blocks: Option<Vec<_>> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt_global(secret_key))
            .collect();
        decrypted_blocks.map(LongPseudonym)
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        let decrypted_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt_global(secret_key))
            .collect();
        LongPseudonym(decrypted_blocks)
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
        let rerandomized_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.rerandomize_known(factor))
            .collect();
        LongEncryptedPseudonym(rerandomized_blocks)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor<G>,
    ) -> Self {
        let rerandomized_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.rerandomize_known(public_key, factor))
            .collect();
        LongEncryptedPseudonym(rerandomized_blocks)
    }
}

// Implement Encrypted for LongEncryptedAttribute
impl<G: Group> Encrypted for LongEncryptedAttribute<G> {
    type Group = G;
    type UnencryptedType = LongAttribute<G>;
    type SecretKeyType = AttributeSessionSecretKey<G>;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = AttributeGlobalSecretKey<G>;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        let decrypted_blocks: Option<Vec<_>> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt(secret_key))
            .collect();
        decrypted_blocks.map(LongAttribute)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Self::UnencryptedType {
        let decrypted_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt(secret_key))
            .collect();
        LongAttribute(decrypted_blocks)
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        let decrypted_blocks: Option<Vec<_>> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt_global(secret_key))
            .collect();
        decrypted_blocks.map(LongAttribute)
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        let decrypted_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.decrypt_global(secret_key))
            .collect();
        LongAttribute(decrypted_blocks)
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let r = G::random_scalar(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
        let rerandomized_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.rerandomize_known(factor))
            .collect();
        LongEncryptedAttribute(rerandomized_blocks)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor<G>,
    ) -> Self {
        let rerandomized_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.rerandomize_known(public_key, factor))
            .collect();
        LongEncryptedAttribute(rerandomized_blocks)
    }
}

// Transcryption trait implementations for long types

impl<G: Group> Pseudonymizable for LongEncryptedPseudonym<G> {
    fn pseudonymize_raw(&self, info: &PseudonymizationInfo<G>) -> Self {
        let ski = info.s.0 * G::scalar_inverse(&info.k.0);
        let pseudonymized_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| {
                #[cfg(feature = "elgamal3")]
                let value = crate::elgamal::primitives::rsk_precomputed(
                    block.value(),
                    &info.s.0,
                    &info.k.0,
                    &ski,
                );
                #[cfg(not(feature = "elgamal3"))]
                let value =
                    crate::elgamal::primitives::rsk_precomputed(block.value(), &info.s.0, &ski);
                EncryptedPseudonym::from_value(value)
            })
            .collect();
        LongEncryptedPseudonym(pseudonymized_blocks)
    }
}

impl<G: Group> Rekeyable for LongEncryptedPseudonym<G> {
    type RekeyInfo = PseudonymRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        let k_inv = G::scalar_inverse(&info.k.0);
        let rekeyed_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| {
                #[cfg(feature = "elgamal3")]
                let value =
                    crate::elgamal::primitives::rekey_precomputed(block.value(), &info.k.0, &k_inv);
                #[cfg(not(feature = "elgamal3"))]
                let value = crate::elgamal::primitives::rekey_precomputed(block.value(), &k_inv);
                EncryptedPseudonym::from_value(value)
            })
            .collect();
        LongEncryptedPseudonym(rekeyed_blocks)
    }
}

impl<G: Group> Rekeyable for LongEncryptedAttribute<G> {
    type RekeyInfo = AttributeRekeyInfo<G>;

    fn rekey_raw(&self, info: &Self::RekeyInfo) -> Self {
        let k_inv = G::scalar_inverse(&info.k.0);
        let rekeyed_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| {
                #[cfg(feature = "elgamal3")]
                let value =
                    crate::elgamal::primitives::rekey_precomputed(block.value(), &info.k.0, &k_inv);
                #[cfg(not(feature = "elgamal3"))]
                let value = crate::elgamal::primitives::rekey_precomputed(block.value(), &k_inv);
                EncryptedAttribute::from_value(value)
            })
            .collect();
        LongEncryptedAttribute(rekeyed_blocks)
    }
}

impl<G: Group> Transcryptable for LongEncryptedPseudonym<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        self.pseudonymize_raw(&info.pseudonym)
    }
}

impl<G: Group> Transcryptable for LongEncryptedAttribute<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        self.rekey_raw(&info.attribute)
    }
}

#[cfg(feature = "batch")]
impl<G: Group> crate::data::traits::HasStructure for LongEncryptedPseudonym<G> {
    type Structure = usize;

    fn structure(&self) -> Self::Structure {
        self.0.len()
    }
}

#[cfg(feature = "batch")]
impl<G: Group> crate::data::traits::HasStructure for LongEncryptedAttribute<G> {
    type Structure = usize;

    fn structure(&self) -> Self::Structure {
        self.0.len()
    }
}

#[cfg(feature = "batch")]
impl<G: Group> BatchEncryptable for LongPseudonym<G> {
    fn preprocess_batch(items: &[Self]) -> Result<Vec<Self>, BatchError> {
        Ok(items.to_vec())
    }
}

#[cfg(feature = "batch")]
impl<G: Group> BatchEncryptable for LongAttribute<G> {
    fn preprocess_batch(items: &[Self]) -> Result<Vec<Self>, BatchError> {
        Ok(items.to_vec())
    }
}

/// Internal helper function to encode bytes with PKCS#7 padding
fn from_bytes_padded_impl<T: ElGamalEncryptable>(data: &[u8]) -> Vec<T>
where
    T::Group: InvertibleEncoding,
{
    let block_length = <T::Group as InvertibleEncoding>::BLOCK_LENGTH;
    // Calculate number of full blocks
    let full_blocks = data.len() / block_length;
    let remaining = data.len() % block_length;

    // We always need at least one block for padding (even for empty data)
    let total_blocks = if data.is_empty() { 1 } else { full_blocks + 1 };
    let mut result = Vec::with_capacity(total_blocks);

    // Add all full blocks from the input data
    for i in 0..full_blocks {
        let start = i * block_length;
        let mut block = <T::Group as InvertibleEncoding>::Block::zeroed();
        block
            .as_mut()
            .copy_from_slice(&data[start..start + block_length]);
        result.push(T::from_lizard(&block));
    }

    // Create the final block with PKCS#7 padding
    let padding_byte = (block_length - remaining) as u8;
    let mut last_block = <T::Group as InvertibleEncoding>::Block::zeroed();
    last_block.as_mut().fill(padding_byte);

    if remaining > 0 {
        last_block.as_mut()[..remaining].copy_from_slice(&data[data.len() - remaining..]);
    }

    result.push(T::from_lizard(&last_block));

    result
}

/// Internal helper function to decode padded bytes.
///
/// This function automatically detects and removes external padding blocks
/// created by `pad_to()`, ensuring that normalized values decode correctly.
///
/// External padding uses all-zero blocks `[0x00, ...]` which are impossible
/// in valid PKCS#7 padding (valid padding bytes are never zero).
fn to_bytes_padded_impl<T: ElGamalEncryptable>(items: &[T]) -> Result<Vec<u8>, Error>
where
    T::Group: InvertibleEncoding,
{
    if items.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "No encryptables provided",
        ));
    }

    // Scan backwards from the end to remove external padding blocks (all-zero blocks)
    // Stop when we find a non-padding block (which will have PKCS#7 padding)
    let mut last_data_block_idx = items.len() - 1;
    while last_data_block_idx > 0 {
        let block = items[last_data_block_idx].to_lizard().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Encryptable conversion to bytes failed",
        ))?;

        if is_external_padding_block::<<T::Group as InvertibleEncoding>::Block>(block.as_ref()) {
            // This is external padding, continue scanning backwards
            last_data_block_idx -= 1;
        } else {
            // Found a data block, stop scanning
            break;
        }
    }

    let mut result = Vec::with_capacity(
        (last_data_block_idx + 1) * <T::Group as InvertibleEncoding>::BLOCK_LENGTH,
    );

    // Copy all blocks except the last data block
    for item in items.iter().take(last_data_block_idx) {
        let block = item.to_lizard().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Encryptable conversion to bytes failed",
        ))?;
        result.extend_from_slice(block.as_ref());
    }

    // Process the last data block and validate PKCS#7 padding
    let last_block = items[last_data_block_idx].to_lizard().ok_or(Error::new(
        ErrorKind::InvalidData,
        "Last encryptable conversion to bytes failed",
    ))?;
    result.extend_from_slice(&unpad_block(last_block.as_ref())?);

    Ok(result)
}
