//! PKCS#7 padding support for single-block (16 byte) encoding.
//!
//! This module provides the `Padded` trait for encoding data up to 15 bytes using PKCS#7 padding.
//! For multi-block data, see the `long` module.

use crate::data::simple::{Attribute, ElGamalEncryptable, Pseudonym};
use std::io::{Error, ErrorKind};

/// A trait for encryptable types that support PKCS#7 padding for single-block (16 byte) encoding.
pub trait Padded: ElGamalEncryptable {
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

        Ok(Self::from_lizard(&block))
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
        let block = self.to_lizard().ok_or(Error::new(
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    // Generic test helper functions

    fn test_from_bytes_padded_roundtrip<T: Padded>() {
        let test_cases = [
            b"" as &[u8],
            b"a",
            b"hello",
            b"Hello, world!",
            b"123456789012345", // 15 bytes (max)
        ];

        for data in test_cases {
            let value = T::from_bytes_padded(data).unwrap();
            let decoded = value.to_bytes_padded().unwrap();
            assert_eq!(data, decoded.as_slice(), "Failed for input: {:?}", data);
        }
    }

    fn test_from_string_padded_roundtrip<T: Padded>() {
        let test_cases = ["", "a", "hello", "Hello, world!", "123456789012345"];

        for text in test_cases {
            let value = T::from_string_padded(text).unwrap();
            let decoded = value.to_string_padded().unwrap();
            assert_eq!(text, decoded.as_str(), "Failed for input: {:?}", text);
        }
    }

    fn test_too_long<T: Padded + std::fmt::Debug>() {
        let data = b"This is 16 bytes"; // Exactly 16 bytes
        let result = T::from_bytes_padded(data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);

        let data = b"This is way more than 15 bytes!";
        let result = T::from_bytes_padded(data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);

        let text = "This is way more than 15 bytes!";
        let result = T::from_string_padded(text);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    fn test_padding_correctness<T: Padded + ElGamalEncryptable>() {
        // Test empty data (should pad with 16 bytes of value 16)
        let value = T::from_bytes_padded(b"").unwrap();
        let bytes = value.to_lizard().unwrap();
        assert_eq!([16u8; 16], bytes);

        // Test 1 byte (should pad with 15 bytes of value 15)
        let value = T::from_bytes_padded(b"X").unwrap();
        let bytes = value.to_lizard().unwrap();
        assert_eq!(b'X', bytes[0]);
        for byte in bytes.iter().skip(1) {
            assert_eq!(15, *byte);
        }

        // Test 15 bytes (should pad with 1 byte of value 1)
        let data = b"123456789012345";
        let value = T::from_bytes_padded(data).unwrap();
        let bytes = value.to_lizard().unwrap();
        assert_eq!(data, &bytes[..15]);
        assert_eq!(1, bytes[15]);
    }

    fn test_invalid_padding_decode<T: Padded + ElGamalEncryptable>() {
        // Create a value with invalid padding (padding byte = 0)
        let invalid_block = [0u8; 16];
        let value = T::from_lizard(&invalid_block);
        let result = value.to_bytes_padded();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);

        // Create a value with inconsistent padding
        let mut inconsistent_block = [5u8; 16];
        inconsistent_block[15] = 6; // Wrong padding byte
        let value = T::from_lizard(&inconsistent_block);
        let result = value.to_bytes_padded();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);

        // Create a value with padding byte > 16
        let mut invalid_block = [17u8; 16];
        invalid_block[0] = b'X'; // Some data
        let value = T::from_lizard(&invalid_block);
        let result = value.to_bytes_padded();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }

    fn test_roundtrip_all_sizes<T: Padded>() {
        // Test roundtrip for all possible data sizes (0-15 bytes)
        for size in 0..=15 {
            let data = vec![b'X'; size];
            let value = T::from_bytes_padded(&data).unwrap();
            let decoded = value.to_bytes_padded().unwrap();
            assert_eq!(data, decoded, "Failed for size {}", size);
        }
    }

    // Pseudonym tests

    #[test]
    fn pseudonym_from_bytes_padded() {
        test_from_bytes_padded_roundtrip::<Pseudonym>();
    }

    #[test]
    fn pseudonym_from_string_padded() {
        test_from_string_padded_roundtrip::<Pseudonym>();
    }

    #[test]
    fn pseudonym_too_long() {
        test_too_long::<Pseudonym>();
    }

    #[test]
    fn pseudonym_padding_correctness() {
        test_padding_correctness::<Pseudonym>();
    }

    #[test]
    fn pseudonym_invalid_padding_decode() {
        test_invalid_padding_decode::<Pseudonym>();
    }

    #[test]
    fn pseudonym_roundtrip_all_sizes() {
        test_roundtrip_all_sizes::<Pseudonym>();
    }

    // Attribute tests

    #[test]
    fn attribute_from_bytes_padded() {
        test_from_bytes_padded_roundtrip::<Attribute>();
    }

    #[test]
    fn attribute_from_string_padded() {
        test_from_string_padded_roundtrip::<Attribute>();
    }

    #[test]
    fn attribute_too_long() {
        test_too_long::<Attribute>();
    }

    #[test]
    fn attribute_padding_correctness() {
        test_padding_correctness::<Attribute>();
    }

    #[test]
    fn attribute_invalid_padding_decode() {
        test_invalid_padding_decode::<Attribute>();
    }

    #[test]
    fn attribute_roundtrip_all_sizes() {
        test_roundtrip_all_sizes::<Attribute>();
    }

    // Attribute-specific tests (Unicode handling)

    #[test]
    fn attribute_unicode() {
        let test_cases = [
            "café", // 5 bytes (é is 2 bytes)
            "你好", // 6 bytes (each Chinese char is 3 bytes)
            "🎉",   // 4 bytes (emoji)
        ];

        for text in test_cases {
            let attr = Attribute::from_string_padded(text).unwrap();
            let decoded = attr.to_string_padded().unwrap();
            assert_eq!(text, decoded.as_str(), "Failed for input: {:?}", text);
        }
    }

    #[test]
    fn attribute_unicode_too_long() {
        // A string that looks short but is > 16 bytes in UTF-8
        let text = "你好世界！"; // 15 bytes (5 chars × 3 bytes each)
        let result = Attribute::from_string_padded(text);
        assert!(result.is_ok()); // Should fit

        let text = "你好世界！！"; // 18 bytes (6 chars × 3 bytes each)
        let result = Attribute::from_string_padded(text);
        assert!(result.is_err()); // Should not fit
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }
}
