use crate::high_level::data_types::{
    Attribute, Encryptable, Encrypted, EncryptedAttribute, EncryptedPseudonym, Pseudonym,
};
use derive_more::{Deref, From};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Error, ErrorKind};

/// A trait for encryptable types that support PKCS#7 padding for single-block (16 byte) encoding.
pub trait Padded: Encryptable {
    /// Encodes an arbitrary byte array using PKCS#7 padding.
    ///
    /// # Parameters
    ///
    /// - `data`: The bytes to encode (must be at most 15 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if the data exceeds 15 bytes.
    fn from_bytes_padded(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if data.len() > 15 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Data too long: {} bytes (max 15)", data.len()),
            ));
        }

        // Create padded block using PKCS#7 padding
        let padding_byte = (16 - data.len()) as u8;
        let mut block = [padding_byte; 16];
        block[..data.len()].copy_from_slice(data);

        Ok(Self::from_bytes(&block))
    }

    /// Encodes a string using PKCS#7 padding.
    ///
    /// # Parameters
    ///
    /// - `text`: The string to encode (must be at most 15 bytes when UTF-8 encoded)
    ///
    /// # Errors
    ///
    /// Returns an error if the string exceeds 15 bytes.
    fn from_string_padded(text: &str) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::from_bytes_padded(text.as_bytes())
    }

    /// Decodes back to the original string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The padding is invalid
    /// - The decoded bytes are not valid UTF-8
    /// - The value was not created using `from_bytes_padded` or `from_string_padded`
    fn to_string_padded(&self) -> Result<String, Error> {
        let bytes = self.to_bytes_padded()?;
        String::from_utf8(bytes).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    /// Decodes back to the original byte array.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The padding is invalid
    /// - The value was not created using `from_bytes_padded` or `from_string_padded`
    fn to_bytes_padded(&self) -> Result<Vec<u8>, Error> {
        let block = self.as_bytes().ok_or(Error::new(
            ErrorKind::InvalidData,
            "Value is not a valid padded value",
        ))?;

        let padding_byte = block[15];

        if padding_byte == 0 || padding_byte > 16 {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid padding"));
        }

        if block[16 - padding_byte as usize..]
            .iter()
            .any(|&b| b != padding_byte)
        {
            return Err(Error::new(ErrorKind::InvalidData, "Inconsistent padding"));
        }

        let data_bytes = 16 - padding_byte as usize;
        Ok(block[..data_bytes].to_vec())
    }
}

impl Padded for Pseudonym {}
impl Padded for Attribute {}

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
/// use libpep::high_level::padding::LongPseudonym;
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
/// use libpep::high_level::padding::LongAttribute;
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
    /// use libpep::high_level::padding::LongPseudonym;
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
    /// use libpep::high_level::padding::LongEncryptedPseudonym;
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
    /// use libpep::high_level::padding::LongEncryptedPseudonym;
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
    /// use libpep::high_level::padding::LongEncryptedAttribute;
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
    /// use libpep::high_level::padding::LongEncryptedAttribute;
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

impl Serialize for LongEncryptedPseudonym {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

impl<'de> Deserialize<'de> for LongEncryptedPseudonym {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for LongEncryptedAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

impl<'de> Deserialize<'de> for LongEncryptedAttribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
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
