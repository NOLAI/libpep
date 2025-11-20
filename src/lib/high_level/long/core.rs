//! Long (multi-block) data types for pseudonyms and attributes.
//!
//! This module provides support for multi-block pseudonyms and attributes that can hold
//! more than 16 bytes of data. These types are built on top of PKCS#7 padding.

use crate::high_level::core::{
    decrypt, encrypt, Attribute, Encryptable, Encrypted, EncryptedAttribute, EncryptedPseudonym,
    HasSessionKeys, Pseudonym,
};
use crate::high_level::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Error, ErrorKind};

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
/// use libpep::high_level::long::core::LongPseudonym;
///
/// let long_pseudo = LongPseudonym::from_string_padded("some-long-identifier1@example.com").unwrap();
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
/// use libpep::high_level::long::core::LongAttribute;
///
/// // This will use the minimum number of blocks needed (may leak length information)
/// let long_attr = LongAttribute::from_string_padded("some long and sensitive data").unwrap();
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongAttribute(pub Vec<Attribute>);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedPseudonym(pub Vec<EncryptedPseudonym>);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct LongEncryptedAttribute(pub Vec<EncryptedAttribute>);

// Implement HasSessionKeys for long types
impl HasSessionKeys for LongPseudonym {
    type SessionPublicKey = PseudonymSessionPublicKey;
    type SessionSecretKey = PseudonymSessionSecretKey;
}

impl HasSessionKeys for LongAttribute {
    type SessionPublicKey = AttributeSessionPublicKey;
    type SessionSecretKey = AttributeSessionSecretKey;
}

impl LongPseudonym {
    /// Encodes an arbitrary byte array into a `LongPseudonym` using PKCS#7 padding.
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
    /// use libpep::high_level::long::core::LongPseudonym;
    ///
    /// let long_pseudo = LongPseudonym::from_bytes_padded(b"participant123456789@abcdef.hij").unwrap();
    /// ```
    pub fn from_bytes_padded(data: &[u8]) -> Result<Self, Error> {
        from_bytes_padded_impl::<Pseudonym>(data).map(LongPseudonym)
    }

    /// Encodes a string into a `LongPseudonym` using PKCS#7 padding.
    ///
    /// # Privacy Warning
    ///
    /// The number of blocks will vary with input size, potentially leaking information
    /// about the data length. Consider padding your data to a fixed size before encoding.
    ///
    /// # Parameters
    ///
    /// - `text`: The string to encode
    pub fn from_string_padded(text: &str) -> Result<Self, Error> {
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
}

impl LongAttribute {
    /// Encodes an arbitrary byte array into a `LongAttribute` using PKCS#7 padding.
    ///
    /// # Privacy Warning
    ///
    /// The number of blocks will vary with input size, potentially leaking information
    /// about the data length. Consider padding your data to a fixed size before encoding.
    ///
    /// # Parameters
    ///
    /// - `data`: The bytes to encode
    pub fn from_bytes_padded(data: &[u8]) -> Result<Self, Error> {
        from_bytes_padded_impl::<Attribute>(data).map(LongAttribute)
    }

    /// Encodes a string into a `LongAttribute` using PKCS#7 padding.
    ///
    /// # Privacy Warning
    ///
    /// The number of blocks will vary with input size, potentially leaking information
    /// about the data length. Consider padding your data to a fixed size before encoding.
    ///
    /// # Parameters
    ///
    /// - `text`: The string to encode
    pub fn from_string_padded(text: &str) -> Result<Self, Error> {
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
}

impl LongEncryptedPseudonym {
    /// Serializes a `LongEncryptedPseudonym` to a string by concatenating the base64-encoded
    /// individual `EncryptedPseudonym` items with "|" as a delimiter.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::high_level::long::core::LongEncryptedPseudonym;
    ///
    /// let long_enc_pseudo = LongEncryptedPseudonym(vec![/* ... */]);
    /// let serialized = long_enc_pseudo.serialize();
    /// ```
    pub fn serialize(&self) -> String {
        self.0
            .iter()
            .map(|item| item.as_base64())
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
    /// use libpep::high_level::long::core::LongEncryptedPseudonym;
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
    /// use libpep::high_level::long::core::LongEncryptedAttribute;
    ///
    /// let long_enc_attr = LongEncryptedAttribute(vec![/* ... */]);
    /// let serialized = long_enc_attr.serialize();
    /// ```
    pub fn serialize(&self) -> String {
        self.0
            .iter()
            .map(|item| item.as_base64())
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
    /// use libpep::high_level::long::core::LongEncryptedAttribute;
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

/// Trait for types that can be encrypted in "long" (multi-block) form.
/// Mirrors the `Encryptable` trait for multi-block types.
pub trait LongEncryptable {
    /// The single-block type that makes up this long type
    type Block: Encryptable + HasSessionKeys;
    /// The encrypted version of this long type
    type EncryptedType: LongEncrypted<UnencryptedType = Self>;

    /// Get the blocks that make up this long type
    fn blocks(&self) -> &[Self::Block];
    /// Create from encrypted blocks (using the Block's EncryptedType)
    fn from_encrypted_blocks(
        blocks: Vec<<Self::Block as Encryptable>::EncryptedType>,
    ) -> Self::EncryptedType;
}

impl LongEncryptable for LongPseudonym {
    type Block = Pseudonym;
    type EncryptedType = LongEncryptedPseudonym;

    fn blocks(&self) -> &[Self::Block] {
        &self.0
    }

    fn from_encrypted_blocks(
        blocks: Vec<<Self::Block as Encryptable>::EncryptedType>,
    ) -> Self::EncryptedType {
        LongEncryptedPseudonym(blocks)
    }
}

impl LongEncryptable for LongAttribute {
    type Block = Attribute;
    type EncryptedType = LongEncryptedAttribute;

    fn blocks(&self) -> &[Self::Block] {
        &self.0
    }

    fn from_encrypted_blocks(
        blocks: Vec<<Self::Block as Encryptable>::EncryptedType>,
    ) -> Self::EncryptedType {
        LongEncryptedAttribute(blocks)
    }
}

/// Trait for long encrypted types that can be decrypted.
/// Mirrors the `Encrypted` trait for multi-block types.
pub trait LongEncrypted: Sized {
    /// The unencrypted version of this long encrypted type
    type UnencryptedType: LongEncryptable<EncryptedType = Self>;

    /// Get the encrypted blocks that make up this long encrypted type
    fn encrypted_blocks(
        &self,
    ) -> &[<<Self::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType];
    /// Create from decrypted blocks
    fn from_decrypted_blocks(
        blocks: Vec<<Self::UnencryptedType as LongEncryptable>::Block>,
    ) -> Self::UnencryptedType;
    /// Create from encrypted blocks
    fn from_encrypted_blocks(
        blocks: Vec<
            <<Self::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType,
        >,
    ) -> Self;
}

impl LongEncrypted for LongEncryptedPseudonym {
    type UnencryptedType = LongPseudonym;

    fn encrypted_blocks(
        &self,
    ) -> &[<<Self::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType] {
        &self.0
    }

    fn from_decrypted_blocks(
        blocks: Vec<<Self::UnencryptedType as LongEncryptable>::Block>,
    ) -> Self::UnencryptedType {
        LongPseudonym(blocks)
    }

    fn from_encrypted_blocks(
        blocks: Vec<
            <<Self::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType,
        >,
    ) -> Self {
        LongEncryptedPseudonym(blocks)
    }
}

impl LongEncrypted for LongEncryptedAttribute {
    type UnencryptedType = LongAttribute;

    fn encrypted_blocks(
        &self,
    ) -> &[<<Self::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType] {
        &self.0
    }

    fn from_decrypted_blocks(
        blocks: Vec<<Self::UnencryptedType as LongEncryptable>::Block>,
    ) -> Self::UnencryptedType {
        LongAttribute(blocks)
    }

    fn from_encrypted_blocks(
        blocks: Vec<
            <<Self::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType,
        >,
    ) -> Self {
        LongEncryptedAttribute(blocks)
    }
}

/// Internal helper function to encode bytes with PKCS#7 padding
fn from_bytes_padded_impl<T: Encryptable>(data: &[u8]) -> Result<Vec<T>, Error> {
    // Handle empty data
    if data.is_empty() {
        return Ok(vec![]);
    }

    // Calculate number of full blocks
    let full_blocks = data.len() / 16;
    let remaining = data.len() % 16;

    // We always need at least one block for padding
    let total_blocks = full_blocks + 1;
    let mut result = Vec::with_capacity(total_blocks);

    // Add all full blocks from the input data
    for i in 0..full_blocks {
        let start = i * 16;
        // Unwrap is safe: slice is exactly 16 bytes by construction
        #[allow(clippy::unwrap_used)]
        result.push(T::from_bytes(&data[start..start + 16].try_into().unwrap()));
    }

    // Create the final block with PKCS#7 padding
    let padding_byte = (16 - remaining) as u8;
    let mut last_block = [padding_byte; 16];

    if remaining > 0 {
        last_block[..remaining].copy_from_slice(&data[data.len() - remaining..]);
    }

    result.push(T::from_bytes(&last_block));

    Ok(result)
}

/// Internal helper function to decode padded bytes
fn to_bytes_padded_impl<T: Encryptable>(items: &[T]) -> Result<Vec<u8>, Error> {
    if items.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "No encryptables provided",
        ));
    }

    let mut result = Vec::with_capacity(items.len() * 16);

    // Copy all blocks except the last one
    for item in items.iter().take(items.len() - 1) {
        let block = item.as_bytes().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Encryptable conversion to bytes failed",
        ))?;
        result.extend_from_slice(&block);
    }

    // Process the last block and validate padding
    // Unwrap is safe: we already checked items.is_empty() above
    #[allow(clippy::unwrap_used)]
    let last_block = items.last().unwrap().as_bytes().ok_or(Error::new(
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

/// Polymorphic encrypt function for long (multi-block) data types.
/// Uses `ops::encrypt` for each individual block.
pub fn encrypt_long<L, R>(
    message: &L,
    public_key: &<L::Block as HasSessionKeys>::SessionPublicKey,
    rng: &mut R,
) -> L::EncryptedType
where
    L: LongEncryptable,
    R: RngCore + CryptoRng,
{
    let encrypted = message
        .blocks()
        .iter()
        .map(|block| encrypt(block, public_key, rng))
        .collect();
    L::from_encrypted_blocks(encrypted)
}

/// Polymorphic decrypt function for long (multi-block) encrypted data types.
/// Uses `ops::decrypt` for each individual block.
pub fn decrypt_long<LE>(
    encrypted: &LE,
    secret_key: &<<LE::UnencryptedType as LongEncryptable>::Block as HasSessionKeys>::SessionSecretKey,
) -> LE::UnencryptedType
where
    LE: LongEncrypted,
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
    <LE::UnencryptedType as LongEncryptable>::Block: HasSessionKeys,
{
    let decrypted = encrypted
        .encrypted_blocks()
        .iter()
        .map(|block| decrypt(block, secret_key))
        .collect();
    LE::from_decrypted_blocks(decrypted)
}

/// Encrypt a long pseudonym using a [`PseudonymSessionPublicKey`].
pub fn encrypt_long_pseudonym<R: RngCore + CryptoRng>(
    message: &LongPseudonym,
    public_key: &PseudonymSessionPublicKey,
    rng: &mut R,
) -> LongEncryptedPseudonym {
    encrypt_long(message, public_key, rng)
}

/// Decrypt a long encrypted pseudonym using a [`PseudonymSessionSecretKey`].
pub fn decrypt_long_pseudonym(
    encrypted: &LongEncryptedPseudonym,
    secret_key: &PseudonymSessionSecretKey,
) -> LongPseudonym {
    decrypt_long(encrypted, secret_key)
}

/// Encrypt a long attribute using an [`AttributeSessionPublicKey`].
pub fn encrypt_long_attribute<R: RngCore + CryptoRng>(
    message: &LongAttribute,
    public_key: &AttributeSessionPublicKey,
    rng: &mut R,
) -> LongEncryptedAttribute {
    encrypt_long(message, public_key, rng)
}

/// Decrypt a long encrypted attribute using an [`AttributeSessionSecretKey`].
pub fn decrypt_long_attribute(
    encrypted: &LongEncryptedAttribute,
    secret_key: &AttributeSessionSecretKey,
) -> LongAttribute {
    decrypt_long(encrypted, secret_key)
}
