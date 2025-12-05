//! Long (multi-block) data types for pseudonyms and attributes.
//!
//! This module provides support for multi-block pseudonyms and attributes that can hold
//! more than 16 bytes of data. These types are built on top of PKCS#7 padding.

use crate::core::data::{
    decrypt, encrypt, Attribute, Encryptable, Encrypted, EncryptedAttribute, EncryptedPseudonym,
    HasSessionKeys, Pseudonym,
};
use crate::core::keys::{
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
/// use libpep::core::long::data::LongPseudonym;
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
/// use libpep::core::long::data::LongAttribute;
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
    /// use libpep::core::long::data::LongPseudonym;
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
    /// use libpep::core::long::data::LongAttribute;
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
}

impl LongEncryptedPseudonym {
    /// Serializes a `LongEncryptedPseudonym` to a string by concatenating the base64-encoded
    /// individual `EncryptedPseudonym` items with "|" as a delimiter.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::core::long::data::LongEncryptedPseudonym;
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
    /// use libpep::core::long::data::LongEncryptedPseudonym;
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
    /// use libpep::core::long::data::LongEncryptedAttribute;
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
    /// use libpep::core::long::data::LongEncryptedAttribute;
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
fn from_bytes_padded_impl<T: Encryptable>(data: &[u8]) -> Vec<T> {
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
        let block = item.to_lizard().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Encryptable conversion to bytes failed",
        ))?;
        result.extend_from_slice(&block);
    }

    // Process the last block and validate padding
    // Unwrap is safe: we already checked items.is_empty() above
    #[allow(clippy::unwrap_used)]
    let last_block = items.last().unwrap().to_lizard().ok_or(Error::new(
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
/// With the `elgamal3` feature, returns `None` if any block fails to decrypt.
#[cfg(feature = "elgamal3")]
pub fn decrypt_long<LE>(
    encrypted: &LE,
    secret_key: &<<LE::UnencryptedType as LongEncryptable>::Block as HasSessionKeys>::SessionSecretKey,
) -> Option<LE::UnencryptedType>
where
    LE: LongEncrypted,
    <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
        Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
    <LE::UnencryptedType as LongEncryptable>::Block: HasSessionKeys,
{
    let decrypted: Option<Vec<_>> = encrypted
        .encrypted_blocks()
        .iter()
        .map(|block| decrypt(block, secret_key))
        .collect();
    decrypted.map(LE::from_decrypted_blocks)
}

/// Polymorphic decrypt function for long (multi-block) encrypted data types.
/// Uses `ops::decrypt` for each individual block.
#[cfg(not(feature = "elgamal3"))]
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
/// With the `elgamal3` feature, returns `None` if any block fails to decrypt.
#[cfg(feature = "elgamal3")]
pub fn decrypt_long_pseudonym(
    encrypted: &LongEncryptedPseudonym,
    secret_key: &PseudonymSessionSecretKey,
) -> Option<LongPseudonym> {
    decrypt_long(encrypted, secret_key)
}

/// Decrypt a long encrypted pseudonym using a [`PseudonymSessionSecretKey`].
#[cfg(not(feature = "elgamal3"))]
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
/// With the `elgamal3` feature, returns `None` if any block fails to decrypt.
#[cfg(feature = "elgamal3")]
pub fn decrypt_long_attribute(
    encrypted: &LongEncryptedAttribute,
    secret_key: &AttributeSessionSecretKey,
) -> Option<LongAttribute> {
    decrypt_long(encrypted, secret_key)
}

/// Decrypt a long encrypted attribute using an [`AttributeSessionSecretKey`].
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt_long_attribute(
    encrypted: &LongEncryptedAttribute,
    secret_key: &AttributeSessionSecretKey,
) -> LongAttribute {
    decrypt_long(encrypted, secret_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::keys::{make_attribute_session_keys, make_pseudonym_session_keys};
    use crate::core::transcryption::contexts::EncryptionContext;
    use crate::core::transcryption::secrets::EncryptionSecret;
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
            &crate::core::keys::make_pseudonym_global_keys(&mut rng).1,
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
            &crate::core::keys::make_attribute_global_keys(&mut rng).1,
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
            &crate::core::keys::make_pseudonym_global_keys(&mut rng).1,
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
        use crate::core::padding::Padded;

        let mut rng = rand::rng();
        let (session_public, _session_secret) = make_pseudonym_session_keys(
            &crate::core::keys::make_pseudonym_global_keys(&mut rng).1,
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
}
