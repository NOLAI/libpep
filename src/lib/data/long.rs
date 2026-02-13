//! Long (multi-block) data types for pseudonyms and attributes.
//!
//! This module provides support for multi-block pseudonyms and attributes that can hold
//! more than 16 bytes of data.
//!
//! # Two Types of Padding
//!
//! This module handles **two distinct types of padding**:
//!
//! ## 1. Internal Padding (PKCS#7)
//!
//! Standard PKCS#7 padding is applied **within** the last data block. This is handled
//! automatically during encoding/decoding:
//! - Ensures data fills complete 16-byte blocks
//! - The padding byte value indicates the number of padding bytes
//! - Always applied, even if data is exactly a multiple of 16 bytes
//!
//! **Examples:**
//!
//! ```text
//! "hello" (5 bytes):
//! Block 1: [h e l l o | 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
//!          └─ data ─┘ └──────────────── 11 padding bytes ────────────────────┘
//!          (padding value = 11 because we need 11 bytes to fill the block)
//!
//! "0123456789ABCDEF" (exactly 16 bytes):
//! Block 1: [0 1 2 3 4 5 6 7 8 9 A B C D E F]  ← full data block
//! Block 2: [0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10]
//!          └──────────────────── full padding block (16 bytes) ───────────────────────────┘
//!
//! "hello world!" (12 bytes):
//! Block 1: [h e l l o   w o r l d ! | 0x04 0x04 0x04 0x04]
//!          └────────── data ──────────┘ └── 4 padding bytes ──┘
//! ```
//!
//! ## 2. External Padding (for Batch Unlinkability)
//!
//! External padding adds **full blocks** to ensure all values in a batch have identical
//! structure, which is required for unlinkable batch transcryption:
//! - Added using the `pad_to(n)` method (optional, not automatic)
//! - Each padding block contains a magic marker and metadata about the original data size
//! - Format: `[0xFF, 0xEE, 0xDD, 0xCC, original_count (8 bytes u64 LE), 0x00, 0x00, 0x00, 0x00]`
//! - The magic marker is impossible in PKCS#7 (valid padding bytes are 0x01-0x10), making it unambiguous
//! - Automatically detected and removed during decoding
//!
//! **Example:** Padding "hello" from 1 block to 3 blocks:
//!
//! ```text
//! Original (1 block):
//! Block 1: [h e l l o | 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]
//!
//! After pad_to(3):
//! Block 1: [h e l l o | 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]  ← original data
//! Block 2: [0xFF 0xEE 0xDD 0xCC | 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00]
//!          └─── magic marker ──┘ └─── original_count=1 (u64 LE) ────┘ └── zeros ──┘
//! Block 3: [0xFF 0xEE 0xDD 0xCC | 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00]
//!          └────────────────── external padding block (same pattern) ──────────────────────┘
//! ```
//!
//! **Why external padding?** In batch transcryption, all values must have identical structure
//! to prevent linkability attacks. External padding normalizes different-sized values to the
//! same structure without modifying their content.
//!
//! **Batch use case:**
//! ```text
//! User A: "id123"              → 1 block → pad_to(3) → 3 blocks
//! User B: "user@example.com"   → 2 blocks → pad_to(3) → 3 blocks
//! Both now have identical structure (3 blocks), preventing linkability during batch transcryption.
//! ```

use crate::arithmetic::scalars::ScalarNonZero;
use crate::data::simple::{
    Attribute, ElGamalEncryptable, ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym,
    Pseudonym,
};
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::TranscryptionInfo;
use crate::factors::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
};
#[cfg(feature = "offline")]
use crate::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
use crate::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Error, ErrorKind};

#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};

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
pub struct LongPseudonym(pub Vec<Pseudonym>);

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
pub struct LongAttribute(pub Vec<Attribute>);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedPseudonym(pub Vec<EncryptedPseudonym>);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedAttribute(pub Vec<EncryptedAttribute>);

impl LongPseudonym {
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
        LongPseudonym(from_bytes_padded_impl::<Pseudonym>(data))
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
    /// - Appends one or more **external padding blocks** after the data blocks
    ///   using a magic marker pattern:
    ///   `[0xFF, 0xEE, 0xDD, 0xCC, original_count (8 bytes u64 LE), 0x00, 0x00, 0x00, 0x00]`
    /// - These blocks are **separate from** the internal PKCS#7 padding within blocks
    /// - External padding is automatically detected and removed during decoding
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

        // Create external padding blocks with metadata about the original block count
        let padding_pattern = create_external_padding_block(current_blocks);
        let padding_block = Pseudonym::from_lizard(&padding_pattern);

        let mut blocks = self.0.clone();
        blocks.resize(target_blocks, padding_block);

        Ok(LongPseudonym(blocks))
    }
}

impl LongAttribute {
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
        LongAttribute(from_bytes_padded_impl::<Attribute>(data))
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
    /// Any additional padding blocks use a special magic-marker format
    /// `[0xFF, 0xEE, 0xDD, 0xCC, original_count (8 bytes u64 LE), 0x00, 0x00, 0x00, 0x00]`
    /// and are automatically detected and skipped during decoding.
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

        // Create external padding blocks with metadata about the original block count
        let padding_pattern = create_external_padding_block(current_blocks);
        let padding_block = Attribute::from_lizard(&padding_pattern);

        let mut blocks = self.0.clone();
        blocks.resize(target_blocks, padding_block);

        Ok(LongAttribute(blocks))
    }
}

impl LongEncryptedPseudonym {
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

        let items: Result<Vec<EncryptedPseudonym>, Error> = s
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

impl LongEncryptedAttribute {
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

        let items: Result<Vec<EncryptedAttribute>, Error> = s
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
impl Serialize for LongEncryptedPseudonym {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for LongEncryptedPseudonym {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl Serialize for LongEncryptedAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for LongEncryptedAttribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
    }
}

/// A marker trait for encryptable types that use multi-block (long) encryption.
pub trait LongEncryptable {
    /// The encrypted type
    type EncryptedType: LongEncrypted;

    /// The single-block type that makes up this long type
    type Block: ElGamalEncryptable;

    /// Get the blocks that make up this long type
    fn blocks(&self) -> &[Self::Block];

    /// Create the encrypted long type from encrypted blocks
    fn from_encrypted_blocks(
        blocks: Vec<<Self::Block as Encryptable>::EncryptedType>,
    ) -> Self::EncryptedType;
}

impl LongEncryptable for LongPseudonym {
    type EncryptedType = LongEncryptedPseudonym;
    type Block = Pseudonym;

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
impl Encryptable for LongPseudonym {
    type EncryptedType = LongEncryptedPseudonym;
    type PublicKeyType = PseudonymSessionPublicKey;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = PseudonymGlobalPublicKey;

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

impl LongEncryptable for LongAttribute {
    type EncryptedType = LongEncryptedAttribute;
    type Block = Attribute;

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
impl Encryptable for LongAttribute {
    type EncryptedType = LongEncryptedAttribute;
    type PublicKeyType = AttributeSessionPublicKey;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = AttributeGlobalPublicKey;

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

/// A marker trait for long encrypted types that can be decrypted.
pub trait LongEncrypted {
    /// The unencrypted type
    type UnencryptedType: LongEncryptable;

    /// The single-block encrypted type that makes up this long encrypted type
    type EncryptedBlock: ElGamalEncrypted;

    /// Get the encrypted blocks that make up this long encrypted type
    fn encrypted_blocks(&self) -> &[Self::EncryptedBlock];

    /// Create from decrypted blocks
    fn from_decrypted_blocks(
        blocks: Vec<<Self::EncryptedBlock as Encrypted>::UnencryptedType>,
    ) -> Self::UnencryptedType;

    /// Create from encrypted blocks
    fn from_encrypted_blocks(blocks: Vec<Self::EncryptedBlock>) -> Self;
}

impl LongEncrypted for LongEncryptedPseudonym {
    type UnencryptedType = LongPseudonym;
    type EncryptedBlock = EncryptedPseudonym;

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

impl LongEncrypted for LongEncryptedAttribute {
    type UnencryptedType = LongAttribute;
    type EncryptedBlock = EncryptedAttribute;

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
impl Encrypted for LongEncryptedPseudonym {
    type UnencryptedType = LongPseudonym;
    type SecretKeyType = PseudonymSessionSecretKey;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = PseudonymGlobalSecretKey;

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
        let r = ScalarNonZero::random(rng);
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
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor) -> Self {
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
        factor: &RerandomizeFactor,
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
impl Encrypted for LongEncryptedAttribute {
    type UnencryptedType = LongAttribute;
    type SecretKeyType = AttributeSessionSecretKey;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = AttributeGlobalSecretKey;

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
        let r = ScalarNonZero::random(rng);
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
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor) -> Self {
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
        factor: &RerandomizeFactor,
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

impl Pseudonymizable for LongEncryptedPseudonym {
    fn pseudonymize(&self, info: &PseudonymizationInfo) -> Self {
        let pseudonymized_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.pseudonymize(info))
            .collect();
        LongEncryptedPseudonym(pseudonymized_blocks)
    }
}

impl Rekeyable for LongEncryptedPseudonym {
    type RekeyInfo = PseudonymRekeyInfo;

    fn rekey(&self, info: &Self::RekeyInfo) -> Self {
        let rekeyed_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.rekey(info))
            .collect();
        LongEncryptedPseudonym(rekeyed_blocks)
    }
}

impl Rekeyable for LongEncryptedAttribute {
    type RekeyInfo = AttributeRekeyInfo;

    fn rekey(&self, info: &Self::RekeyInfo) -> Self {
        let rekeyed_blocks: Vec<_> = self
            .encrypted_blocks()
            .iter()
            .map(|block| block.rekey(info))
            .collect();
        LongEncryptedAttribute(rekeyed_blocks)
    }
}

impl Transcryptable for LongEncryptedPseudonym {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        self.pseudonymize(&info.pseudonym)
    }
}

impl Transcryptable for LongEncryptedAttribute {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        self.rekey(&info.attribute)
    }
}

#[cfg(feature = "batch")]
impl crate::data::traits::HasStructure for LongEncryptedPseudonym {
    type Structure = usize;

    fn structure(&self) -> Self::Structure {
        self.0.len()
    }
}

#[cfg(feature = "batch")]
impl crate::data::traits::HasStructure for LongEncryptedAttribute {
    type Structure = usize;

    fn structure(&self) -> Self::Structure {
        self.0.len()
    }
}

/// Internal helper function to encode bytes with PKCS#7 padding
fn from_bytes_padded_impl<T: ElGamalEncryptable>(data: &[u8]) -> Vec<T> {
    // Calculate number of full blocks
    let full_blocks = data.len() / 16;
    let remaining = data.len() % 16;

    // We always need at least one block for padding (even for empty data)
    let total_blocks = if data.is_empty() { 1 } else { full_blocks + 1 };
    let mut result = Vec::with_capacity(total_blocks);

    // Add all full blocks from the input data
    for i in 0..full_blocks {
        let start = i * 16;
        // Unwrap is safe: slice is exactly 16 bytes by construction
        #[allow(clippy::unwrap_used)]
        result.push(T::from_lizard(&data[start..start + 16].try_into().unwrap()));
    }

    // Create the final block with PKCS#7 padding
    let padding_byte = (16 - remaining) as u8;
    let mut last_block = [padding_byte; 16];

    if remaining > 0 {
        last_block[..remaining].copy_from_slice(&data[data.len() - remaining..]);
    }

    result.push(T::from_lizard(&last_block));

    result
}

/// Magic marker for external padding blocks.
/// This sequence is impossible in valid PKCS#7 padding for 16-byte blocks
/// (valid padding bytes are 0x01-0x10, so 0xFF is impossible).
const EXTERNAL_PADDING_MAGIC: [u8; 4] = [0xFF, 0xEE, 0xDD, 0xCC];

/// Creates an external padding block with metadata about the original block count.
///
/// Format: [0xFF, 0xEE, 0xDD, 0xCC, original_count (8 bytes as u64 LE), 0x00, 0x00, 0x00, 0x00]
///
/// The magic marker (0xFF, 0xEE, 0xDD, 0xCC) is impossible in PKCS#7 padding for 16-byte blocks,
/// making this unambiguous. The original block count allows the decoder to know exactly where
/// the real data ends and external padding begins.
fn create_external_padding_block(original_block_count: usize) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[0..4].copy_from_slice(&EXTERNAL_PADDING_MAGIC);
    block[4..12].copy_from_slice(&(original_block_count as u64).to_le_bytes());
    // Remaining 4 bytes stay as 0x00
    block
}

/// Checks if a block is an external padding block and extracts the original block count.
///
/// Returns `Some(original_block_count)` if this is an external padding block,
/// or `None` if this is a regular data block.
///
/// # Disambiguation Guarantee
///
/// - External padding blocks **always** end with `[0x00, 0x00, 0x00, 0x00]`
/// - PKCS#7 data blocks **never** have `0x00` in the last byte (valid padding: `0x01`-`0x10`)
///
/// This means **ALL possible byte sequences can be encoded without ambiguity**, including:
/// - Data starting with the magic marker `[0xFF, 0xEE, 0xDD, 0xCC]`
/// - Data exactly matching the external padding pattern
/// - Any combination of bytes whatsoever
fn is_external_padding_block(block: &[u8]) -> Option<usize> {
    if block.len() != 16 {
        return None;
    }

    // Check magic marker
    if block[0..4] != EXTERNAL_PADDING_MAGIC {
        return None;
    }

    // Check that last 4 bytes are zeros (as created by create_external_padding_block)
    // This prevents false positives where legitimate data happens to start with the magic marker
    if block[12..16] != [0x00, 0x00, 0x00, 0x00] {
        return None;
    }

    // Extract original block count
    let count_bytes: [u8; 8] = match block[4..12].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };

    Some(u64::from_le_bytes(count_bytes) as usize)
}

/// Internal helper function to decode padded bytes.
///
/// This function automatically detects and skips external padding blocks
/// created by `pad_to()`, ensuring that normalized values decode correctly.
///
/// External padding uses a magic marker `[0xFF, 0xEE, 0xDD, 0xCC, ...]` which is
/// impossible in valid PKCS#7 padding (valid padding bytes are 0x01-0x10).
fn to_bytes_padded_impl<T: ElGamalEncryptable>(items: &[T]) -> Result<Vec<u8>, Error> {
    if items.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "No encryptables provided",
        ));
    }

    // Check if there are external padding blocks at the end
    // If so, extract the original block count from them
    let last_data_block_idx = if !items.is_empty() {
        let last_block = items[items.len() - 1].to_lizard().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Encryptable conversion to bytes failed",
        ))?;

        if let Some(original_count) = is_external_padding_block(&last_block) {
            // We have external padding, use the encoded original block count
            // Check for underflow: original_count must be at least 1
            if original_count == 0 || original_count > items.len() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "External padding contains invalid block count",
                ));
            }
            original_count - 1 // -1 because we use it as an index
        } else {
            // No external padding, last block is the last data block
            items.len() - 1
        }
    } else {
        return Err(Error::new(ErrorKind::InvalidData, "Empty data"));
    };

    let mut result = Vec::with_capacity((last_data_block_idx + 1) * 16);

    // Copy all blocks except the last data block
    for item in items.iter().take(last_data_block_idx) {
        let block = item.to_lizard().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Encryptable conversion to bytes failed",
        ))?;
        result.extend_from_slice(&block);
    }

    // Process the last data block and validate PKCS#7 padding
    let last_block = items[last_data_block_idx].to_lizard().ok_or(Error::new(
        ErrorKind::InvalidData,
        "Last encryptable conversion to bytes failed",
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::encrypt;
    use crate::factors::contexts::EncryptionContext;
    use crate::factors::EncryptionSecret;
    use crate::keys::{make_attribute_session_keys, make_pseudonym_session_keys};
    use std::io::ErrorKind;

    #[test]
    fn long_attribute_from_bytes_padded_empty() {
        let data: &[u8] = &[];
        let result = LongAttribute::from_bytes_padded(data);
        // Empty data should still result in one block with full padding (PKCS#7)
        assert_eq!(result.len(), 1);
        // The block should be all padding bytes with value 16
        let block_bytes = result[0].to_lizard().unwrap();
        assert_eq!([16u8; 16], block_bytes);
    }

    #[test]
    fn long_attribute_from_bytes_padded_single_block() {
        let data = b"Hello, world!";
        let result = LongAttribute::from_bytes_padded(data);

        assert_eq!(1, result.len());

        // The padding should be 3 bytes of value 3
        let bytes = result[0].to_lizard().unwrap();
        assert_eq!(b"Hello, world!\x03\x03\x03", &bytes);
    }

    #[test]
    fn long_attribute_from_bytes_padded_exact_block() {
        let data = b"0123456789ABCDEF";
        let result = LongAttribute::from_bytes_padded(data);

        // Should have 2 blocks: the 16 bytes of data and one full block of padding
        assert_eq!(2, result.len());

        // First block should be exactly our input
        assert_eq!(b"0123456789ABCDEF", &result[0].to_lizard().unwrap());

        // Second block should be all padding bytes with value 16
        let expected_padding = [16u8; 16];
        assert_eq!(expected_padding, result[1].to_lizard().unwrap());
    }

    #[test]
    fn long_attribute_from_bytes_padded_multiple_blocks() {
        let data = b"This is a longer string that spans multiple blocks";
        let result = LongAttribute::from_bytes_padded(data);

        // Calculate expected number of blocks (51 bytes -> 4 blocks)
        let expected_blocks = (data.len() / 16) + 1;
        assert_eq!(expected_blocks, result.len());

        // Check the content of each full block
        for (i, block) in result.iter().enumerate().take(data.len() / 16) {
            let start = i * 16;
            let expected = data[start..start + 16].to_vec();
            assert_eq!(expected, block.to_lizard().unwrap()[..16]);
        }

        // Check the last block's padding
        let last_block = result.last().unwrap().to_lizard().unwrap();
        let remaining = data.len() % 16;
        let padding_byte = (16 - remaining) as u8;

        // Verify data portion
        assert_eq!(&data[data.len() - remaining..], &last_block[..remaining]);

        // Verify padding portion
        for byte in last_block.iter().skip(remaining) {
            assert_eq!(&padding_byte, byte);
        }
    }

    #[test]
    fn long_attribute_to_bytes_padded() {
        let original = b"This is some test data for padding";
        let attributes = LongAttribute::from_bytes_padded(original);
        let decoded = attributes.to_bytes_padded().unwrap();
        assert_eq!(original, decoded.as_slice());
    }

    #[test]
    fn long_attribute_to_bytes_padded_empty() {
        let attributes = LongAttribute::from(vec![]);
        let result = attributes.to_bytes_padded();

        assert!(result.is_err());
        assert_eq!(ErrorKind::InvalidInput, result.unwrap_err().kind());
    }

    #[test]
    fn long_attribute_to_bytes_padded_invalid_padding() {
        // Create an Attribute with invalid padding (padding byte = 0)
        let invalid_block = [0u8; 16];
        let attribute = Attribute::from_lizard(&invalid_block);
        let long_attr = LongAttribute::from(vec![attribute]);

        let result = long_attr.to_bytes_padded();
        assert!(result.is_err());
        assert_eq!(ErrorKind::InvalidData, result.unwrap_err().kind());

        // Try with inconsistent padding
        let mut inconsistent_block = [5u8; 16];
        inconsistent_block[15] = 6;
        let attribute = Attribute::from_lizard(&inconsistent_block);
        let long_attr = LongAttribute::from(vec![attribute]);

        let result = long_attr.to_bytes_padded();
        assert!(result.is_err());
    }

    #[test]
    fn long_attribute_to_string_padded() {
        let original = "This is a UTF-8 string with special chars: ñáéíóú 你好";
        let attributes = LongAttribute::from_string_padded(original);
        let decoded = attributes.to_string_padded().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn long_attribute_to_string_padded_invalid_utf8() {
        // Create data points with non-UTF8 data
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let mut block = [0u8; 16];
        block[..3].copy_from_slice(&invalid_utf8);
        block[3..].fill(13); // Padding

        let attribute = Attribute::from_lizard(&block);
        let long_attr = LongAttribute::from(vec![attribute]);

        let result = long_attr.to_string_padded();
        assert!(result.is_err());
    }

    #[test]
    fn long_attribute_roundtrip_all_padding_sizes() {
        for padding_size in 1..=16 {
            let size = 32 - padding_size;
            let data = vec![b'X'; size];

            let attributes = LongAttribute::from_bytes_padded(&data);
            let decoded = attributes.to_bytes_padded().unwrap();

            assert_eq!(data, decoded);
        }
    }

    #[test]
    fn long_pseudonym_from_bytes_padded() {
        let data = b"Hello, world!";
        let result = LongPseudonym::from_bytes_padded(data);

        assert_eq!(1, result.len());

        let bytes = result[0].to_lizard().unwrap();
        assert_eq!(b"Hello, world!\x03\x03\x03", &bytes);
    }

    #[test]
    fn long_pseudonym_to_bytes_padded() {
        let original = b"This is some test data for padding";
        let pseudonyms = LongPseudonym::from_bytes_padded(original);
        let decoded = pseudonyms.to_bytes_padded().unwrap();
        assert_eq!(original, decoded.as_slice());
    }

    #[test]
    fn long_pseudonym_string_roundtrip() {
        let original = "Testing pseudonym string conversion";
        let pseudonyms = LongPseudonym::from_string_padded(original);
        let decoded = pseudonyms.to_string_padded().unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn long_encrypted_pseudonym_serialize_deserialize() {
        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_pseudonym_session_keys(
            &crate::keys::make_pseudonym_global_keys(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let pseudonyms = LongPseudonym::from_string_padded("test-data-for-serialization");
        let encrypted: Vec<EncryptedPseudonym> = pseudonyms
            .iter()
            .map(|p| encrypt(p, &session_public, &mut rng))
            .collect();
        let long_encrypted = LongEncryptedPseudonym::from(encrypted);

        let serialized = long_encrypted.serialize();
        assert!(serialized.contains('|'));

        let deserialized = LongEncryptedPseudonym::deserialize(&serialized).unwrap();
        assert_eq!(long_encrypted.len(), deserialized.len());

        for (original, restored) in long_encrypted.iter().zip(deserialized.iter()) {
            assert_eq!(original, restored);
        }
    }

    #[test]
    fn long_encrypted_attribute_serialize_deserialize() {
        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_attribute_session_keys(
            &crate::keys::make_attribute_global_keys(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let attributes = LongAttribute::from_string_padded("attribute-test-data");
        let encrypted: Vec<_> = attributes
            .iter()
            .map(|a| encrypt(a, &session_public, &mut rng))
            .collect();
        let long_encrypted = LongEncryptedAttribute::from(encrypted);

        let serialized = long_encrypted.serialize();
        assert!(serialized.contains('|'));

        let deserialized = LongEncryptedAttribute::deserialize(&serialized).unwrap();
        assert_eq!(long_encrypted.len(), deserialized.len());

        for (original, restored) in long_encrypted.iter().zip(deserialized.iter()) {
            assert_eq!(original, restored);
        }
    }

    #[test]
    fn long_encrypted_empty_roundtrip() {
        let empty_pseudo = LongEncryptedPseudonym(vec![]);
        let serialized = empty_pseudo.serialize();
        assert_eq!(serialized, "");

        let deserialized = LongEncryptedPseudonym::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.len(), 0);

        let empty_attr = LongEncryptedAttribute(vec![]);
        let serialized = empty_attr.serialize();
        assert_eq!(serialized, "");

        let deserialized = LongEncryptedAttribute::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.len(), 0);
    }

    #[test]
    fn long_encrypted_deserialize_invalid_base64() {
        let result = LongEncryptedPseudonym::deserialize("invalid!!!|also-invalid!!!");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);

        let result = LongEncryptedAttribute::deserialize("invalid!!!|also-invalid!!!");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn long_encrypted_serde_json() {
        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_pseudonym_session_keys(
            &crate::keys::make_pseudonym_global_keys(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let pseudonyms = LongPseudonym::from_string_padded("serde-test-data");
        let encrypted: Vec<EncryptedPseudonym> = pseudonyms
            .iter()
            .map(|p| encrypt(p, &session_public, &mut rng))
            .collect();
        let long_encrypted = LongEncryptedPseudonym::from(encrypted);

        let json = serde_json::to_string(&long_encrypted).expect("Failed to serialize to JSON");
        let deserialized: LongEncryptedPseudonym =
            serde_json::from_str(&json).expect("Failed to deserialize from JSON");

        assert_eq!(long_encrypted.len(), deserialized.len());
        for (original, restored) in long_encrypted.iter().zip(deserialized.iter()) {
            assert_eq!(original, restored);
        }
    }

    #[test]
    fn long_encrypted_pseudonym_single_item() {
        use crate::data::padding::Padded;

        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_pseudonym_session_keys(
            &crate::keys::make_pseudonym_global_keys(&mut rng).1,
            &EncryptionContext::from("session-1"),
            &EncryptionSecret::from("enc-secret".as_bytes().to_vec()),
        );

        let pseudonym = Pseudonym::from_bytes_padded(b"single").unwrap();
        let encrypted = encrypt(&pseudonym, &session_public, &mut rng);
        let long_encrypted = LongEncryptedPseudonym::from(vec![encrypted]);

        // Serialize and deserialize
        let serialized = long_encrypted.serialize();
        assert!(!serialized.contains('|')); // Single item should not have delimiter

        let deserialized = LongEncryptedPseudonym::deserialize(&serialized).unwrap();
        assert_eq!(1, deserialized.len());
        assert_eq!(long_encrypted[0], deserialized[0]);
    }

    #[test]
    fn long_attribute_null_bytes_in_middle() {
        // Test string with null bytes in the middle
        let str_with_nulls = "hello\0world";
        let attr = LongAttribute::from_string_padded(str_with_nulls);
        let decoded = attr.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_attribute_null_bytes_at_end() {
        // Test string ending with null bytes
        let str_ending_nulls = "test\0\0";
        let attr = LongAttribute::from_string_padded(str_ending_nulls);
        let decoded = attr.to_string_padded().unwrap();
        assert_eq!(str_ending_nulls, decoded);
    }

    #[test]
    fn long_attribute_empty_string() {
        // Test empty string
        let empty = "";
        let attr = LongAttribute::from_string_padded(empty);
        let decoded = attr.to_string_padded().unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn long_attribute_strings_ending_with_many_null_bytes() {
        // Test various counts of trailing null bytes
        for null_count in 1..=20 {
            let mut test_str = String::from("test");
            test_str.push_str(&"\0".repeat(null_count));

            let attr = LongAttribute::from_string_padded(&test_str);
            let decoded = attr.to_string_padded().unwrap();

            assert_eq!(test_str, decoded, "Failed for {} null bytes", null_count);
        }
    }

    #[test]
    fn long_attribute_only_null_bytes() {
        // Test strings that are only null bytes
        for null_count in 1..=20 {
            let test_str = "\0".repeat(null_count);

            let attr = LongAttribute::from_string_padded(&test_str);
            let decoded = attr.to_string_padded().unwrap();

            assert_eq!(
                test_str, decoded,
                "Failed for string of {} null bytes",
                null_count
            );
        }
    }

    #[test]
    fn long_attribute_edge_case_15_and_16_null_bytes() {
        // 15 null bytes - exactly fits in one block with 1 byte padding
        let str_15 = "\0".repeat(15);
        let attr_15 = LongAttribute::from_string_padded(&str_15);
        let decoded_15 = attr_15.to_string_padded().unwrap();
        assert_eq!(str_15, decoded_15);

        // 16 null bytes - requires 2 blocks (first full, second with 15 bytes data + 1 padding)
        let str_16 = "\0".repeat(16);
        let attr_16 = LongAttribute::from_string_padded(&str_16);
        let decoded_16 = attr_16.to_string_padded().unwrap();
        assert_eq!(str_16, decoded_16);

        // 17 null bytes
        let str_17 = "\0".repeat(17);
        let attr_17 = LongAttribute::from_string_padded(&str_17);
        let decoded_17 = attr_17.to_string_padded().unwrap();
        assert_eq!(str_17, decoded_17);
    }

    #[test]
    fn long_attribute_pad_to_with_null_bytes() {
        // Create a string with null bytes
        let str_with_nulls = "data\0\0end";
        let attr = LongAttribute::from_string_padded(str_with_nulls);

        // Pad to more blocks
        let padded = attr.pad_to(3).unwrap();

        // Should preserve the null bytes in the original string
        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_attribute_pad_to_only_null_bytes() {
        // Test strings that are only null bytes, then padded
        for null_count in 1..=10 {
            let test_str = "\0".repeat(null_count);

            let attr = LongAttribute::from_string_padded(&test_str);
            let padded = attr.pad_to(5).unwrap();

            let decoded = padded.to_string_padded().unwrap();
            assert_eq!(
                test_str, decoded,
                "Failed for padded string of {} null bytes",
                null_count
            );
        }
    }

    #[test]
    fn long_attribute_pad_to_empty_string() {
        // Test empty string with padding
        let empty = "";
        let attr = LongAttribute::from_string_padded(empty);
        let padded = attr.pad_to(2).unwrap();

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn long_pseudonym_null_bytes_roundtrip() {
        // Test pseudonym with null bytes
        let str_with_nulls = "user\0\0id";
        let pseudo = LongPseudonym::from_string_padded(str_with_nulls);
        let decoded = pseudo.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_pseudonym_pad_to_with_null_bytes() {
        // Test pseudonym with null bytes after padding
        let str_with_nulls = "id\0\0x";
        let pseudo = LongPseudonym::from_string_padded(str_with_nulls);
        let padded = pseudo.pad_to(3).unwrap();

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(str_with_nulls, decoded);
    }

    #[test]
    fn long_attribute_data_ending_with_full_0x10_block() {
        // Regression test for external padding detection:
        // Plaintext containing a full block of 0x10 bytes should roundtrip correctly.
        // After PKCS#7 encoding, this becomes [0x10×16][0x10×16] (data block + padding block).
        // The decoder must correctly identify the second block as legitimate PKCS#7 padding,
        // not external padding added by pad_to().
        let data = vec![0x10u8; 16];
        let attr = LongAttribute::from_bytes_padded(&data);
        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Data ending with full 0x10 block should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_ascending_sequence_data() {
        // Regression test: ensure data containing ascending sequence [0,1,2,...,15]
        // can be encoded and decoded correctly even though it looks like a pattern.
        let data: Vec<u8> = (0..16).collect();
        let attr = LongAttribute::from_bytes_padded(&data);
        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Ascending sequence data should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_pad_to_preserves_data() {
        // Test that pad_to correctly preserves data when adding external padding
        let attr = LongAttribute::from_string_padded("hello");
        let original_len = attr.len();

        let padded = attr.pad_to(original_len + 2).unwrap();
        assert_eq!(
            padded.len(),
            original_len + 2,
            "Padded length should match target"
        );

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(decoded, "hello", "pad_to should preserve original data");
    }

    #[test]
    fn long_pseudonym_pad_to_preserves_data() {
        // Test that pad_to correctly preserves data for pseudonyms
        let pseudo = LongPseudonym::from_string_padded("test-user-id");
        let original_len = pseudo.len();

        let padded = pseudo.pad_to(original_len + 3).unwrap();
        assert_eq!(
            padded.len(),
            original_len + 3,
            "Padded length should match target"
        );

        let decoded = padded.to_string_padded().unwrap();
        assert_eq!(
            decoded, "test-user-id",
            "pad_to should preserve original data"
        );
    }

    #[test]
    fn long_attribute_data_containing_magic_marker_multiblock() {
        // Edge case: Data that contains the magic marker bytes [0xFF, 0xEE, 0xDD, 0xCC]
        // CAN be encoded if it spans multiple blocks (>16 bytes).
        // The magic marker check only applies to the last block.
        let data = vec![
            0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xAA, 0xBB, 0xCC,
        ];
        let attr = LongAttribute::from_bytes_padded(&data);
        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Multi-block data containing magic marker should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_single_block_with_magic_marker() {
        // Edge case: Data starting with magic marker CAN now be encoded
        // because we check that the last 4 bytes are zeros.
        //
        // After PKCS#7: [0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08]
        // Last 4 bytes are [0x08, 0x08, 0x08, 0x08], not [0x00, 0x00, 0x00, 0x00]
        // So this is NOT detected as external padding and roundtrips correctly.
        let data = vec![0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66];
        let attr = LongAttribute::from_bytes_padded(&data);

        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Single-block data starting with magic marker should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_data_exactly_matching_external_padding_pattern() {
        // Edge case: Data that exactly matches our external padding block format.
        // After PKCS#7 encoding, this should still work correctly.
        let data = vec![
            0xFF, 0xEE, 0xDD, 0xCC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let attr = LongAttribute::from_bytes_padded(&data);

        // After PKCS#7: will be 2 blocks: [data][full padding block]
        // The last block will be [0x10×16], not the magic marker
        assert_eq!(attr.len(), 2);

        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Data matching external padding pattern should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_double_pad_to_fails() {
        // Edge case: Calling pad_to() multiple times should fail to decode
        // because the decoder will find nested external padding blocks.
        let attr = LongAttribute::from_string_padded("test");
        let padded_once = attr.pad_to(2).unwrap();
        let padded_twice = padded_once.pad_to(3).unwrap();

        // This should fail because block 1 (external padding with count=1)
        // doesn't have valid PKCS#7 padding
        let result = padded_twice.to_string_padded();
        assert!(result.is_err(), "Double pad_to should fail to decode");
    }

    #[test]
    fn verify_no_ambiguous_edge_cases() {
        // Comprehensive verification that ALL data can be encoded without ambiguity
        // This test confirms the fix for the edge case where single-block data
        // starting with the magic marker [0xFF, 0xEE, 0xDD, 0xCC] previously failed.

        // Test 1: Single-block data starting with magic marker (previously failed)
        let data1 = vec![0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66];
        let attr1 = LongAttribute::from_bytes_padded(&data1);
        let decoded1 = attr1.to_bytes_padded().unwrap();
        assert_eq!(
            data1, decoded1,
            "Single-block data with magic marker should work"
        );

        // Test 2: Exact external padding pattern as data (with PKCS#7, last block differs)
        let data2 = vec![
            0xFF, 0xEE, 0xDD, 0xCC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let attr2 = LongAttribute::from_bytes_padded(&data2);
        let decoded2 = attr2.to_bytes_padded().unwrap();
        assert_eq!(
            data2, decoded2,
            "Data matching external padding pattern should work"
        );

        // Test 3: Magic marker in middle of multi-block data
        let data3 = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xEE, 0xDD, 0xCC, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16,
        ];
        let attr3 = LongAttribute::from_bytes_padded(&data3);
        let decoded3 = attr3.to_bytes_padded().unwrap();
        assert_eq!(data3, decoded3, "Magic marker in middle should work");

        // Test 4: pad_to() still works correctly
        let attr4 = LongAttribute::from_string_padded("hello");
        let padded = attr4.pad_to(3).unwrap();
        assert_eq!(
            padded.len(),
            3,
            "pad_to should create correct number of blocks"
        );
        let decoded4 = padded.to_string_padded().unwrap();
        assert_eq!("hello", decoded4, "pad_to should preserve original data");

        // Test 5: Various lengths starting with magic marker
        for len in 1..=32 {
            let mut data = vec![0xFF, 0xEE, 0xDD, 0xCC];
            data.extend(vec![0xAB; len]);

            let attr = LongAttribute::from_bytes_padded(&data);
            let decoded = attr.to_bytes_padded().unwrap();
            assert_eq!(
                data,
                decoded,
                "Data of length {} starting with magic marker should work",
                len + 4
            );
        }
    }
}
