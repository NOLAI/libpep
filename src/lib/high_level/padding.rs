//! PKCS#7 padding support for single-block (16 byte) encoding.
//!
//! This module provides the `Padded` trait for encoding data up to 15 bytes using PKCS#7 padding.
//! For multi-block data, see the `long_data_types` module.

use crate::high_level::core::{Attribute, Encryptable, Pseudonym};
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
