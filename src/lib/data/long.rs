//! Long (multi-block) data types for pseudonyms and attributes.
//!
//! This module provides support for multi-block pseudonyms and attributes that can hold
//! more than one block (16 bytes on ristretto255) of data.
//!
//! # Padding
//!
//! Long data types use PKCS#7 padding (internal padding) automatically for the last block.
//! They also support optional external padding via the `pad_to()` method for batch unlinkability.
//!
//! For detailed information about the two types of padding, see the [`padding`](crate::data::padding) module.
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances, with same-named functions as
//! their tuple constructors.

pub mod generic;

use crate::data::simple::{
    Attribute, ElGamalEncryptable, ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym,
    Pseudonym,
};
use crate::data::traits::{Encryptable, Encrypted};
use crate::elgamal::arithmetic::Ristretto255;

/// The [`LongPseudonym`](generic::LongPseudonym) over ristretto255.
pub type LongPseudonym = generic::LongPseudonym<Ristretto255>;
/// The [`LongAttribute`](generic::LongAttribute) over ristretto255.
pub type LongAttribute = generic::LongAttribute<Ristretto255>;
/// The [`LongEncryptedPseudonym`](generic::LongEncryptedPseudonym) over ristretto255.
pub type LongEncryptedPseudonym = generic::LongEncryptedPseudonym<Ristretto255>;
/// The [`LongEncryptedAttribute`](generic::LongEncryptedAttribute) over ristretto255.
pub type LongEncryptedAttribute = generic::LongEncryptedAttribute<Ristretto255>;

/// Construct a [`LongPseudonym`](type@LongPseudonym) from its blocks.
#[allow(non_snake_case)]
pub fn LongPseudonym(blocks: Vec<Pseudonym>) -> LongPseudonym {
    generic::LongPseudonym(blocks)
}

/// Construct a [`LongAttribute`](type@LongAttribute) from its blocks.
#[allow(non_snake_case)]
pub fn LongAttribute(blocks: Vec<Attribute>) -> LongAttribute {
    generic::LongAttribute(blocks)
}

/// Construct a [`LongEncryptedPseudonym`](type@LongEncryptedPseudonym) from its encrypted blocks.
#[allow(non_snake_case)]
pub fn LongEncryptedPseudonym(blocks: Vec<EncryptedPseudonym>) -> LongEncryptedPseudonym {
    generic::LongEncryptedPseudonym(blocks)
}

/// Construct a [`LongEncryptedAttribute`](type@LongEncryptedAttribute) from its encrypted blocks.
#[allow(non_snake_case)]
pub fn LongEncryptedAttribute(blocks: Vec<EncryptedAttribute>) -> LongEncryptedAttribute {
    generic::LongEncryptedAttribute(blocks)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::encrypt;
    use crate::contexts::EncryptionContext;
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
    #[cfg(feature = "json")]
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
        // Edge case: Data that contains bytes [0xFF, 0xEE, 0xDD, 0xCC]
        // CAN be encoded regardless - external padding is all zeros now.
        let data = vec![
            0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xAA, 0xBB, 0xCC,
        ];
        let attr = LongAttribute::from_bytes_padded(&data);
        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Multi-block data with any bytes should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_single_block_with_magic_marker() {
        // Edge case: Data starting with [0xFF, 0xEE, 0xDD, 0xCC] works fine.
        // After PKCS#7, the last byte will be 0x08 (padding), not 0x00.
        // External padding is all zeros, so this won't be confused.
        let data = vec![0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66];
        let attr = LongAttribute::from_bytes_padded(&data);

        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(
            data, decoded,
            "Single-block data with any bytes should roundtrip correctly"
        );
    }

    #[test]
    fn long_attribute_data_exactly_matching_external_padding_pattern() {
        // Edge case: Data that is all zeros.
        // After PKCS#7 encoding, the last byte will be a padding value (0x01-0x10), not 0x00.
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let attr = LongAttribute::from_bytes_padded(&data);

        // After PKCS#7: will be 1 block with last byte = 0x01
        // Not all zeros, so won't be confused with external padding
        assert_eq!(attr.len(), 1);

        let decoded = attr.to_bytes_padded().unwrap();
        assert_eq!(data, decoded, "All-zero data should roundtrip correctly");
    }

    #[test]
    fn long_attribute_double_pad_to_works() {
        // With all-zero external padding, calling pad_to() multiple times works correctly.
        // The decoder scans backwards removing all zero blocks until it finds the data block.
        let attr = LongAttribute::from_string_padded("test");
        let padded_once = attr.pad_to(2).unwrap();
        let padded_twice = padded_once.pad_to(3).unwrap();

        // This should succeed - all zero blocks are removed, leaving just the data
        let result = padded_twice.to_string_padded();
        assert!(
            result.is_ok(),
            "Double pad_to should succeed with all-zero padding"
        );
        assert_eq!(result.unwrap(), "test");
    }

    #[test]
    fn verify_no_ambiguous_edge_cases() {
        // Comprehensive verification that ALL data can be encoded without ambiguity
        // External padding is all-zero blocks, and PKCS#7 ensures the last byte is never 0x00.

        // Test 1: Arbitrary data
        let data1 = vec![0xFF, 0xEE, 0xDD, 0xCC, 0x99, 0x88, 0x77, 0x66];
        let attr1 = LongAttribute::from_bytes_padded(&data1);
        let decoded1 = attr1.to_bytes_padded().unwrap();
        assert_eq!(data1, decoded1, "Arbitrary data should work");

        // Test 2: All-zero data (PKCS#7 adds non-zero padding)
        let data2 = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let attr2 = LongAttribute::from_bytes_padded(&data2);
        let decoded2 = attr2.to_bytes_padded().unwrap();
        assert_eq!(data2, decoded2, "All-zero data should work");

        // Test 3: Mixed zeros and non-zeros
        let data3 = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16,
        ];
        let attr3 = LongAttribute::from_bytes_padded(&data3);
        let decoded3 = attr3.to_bytes_padded().unwrap();
        assert_eq!(data3, decoded3, "Mixed data should work");

        // Test 4: pad_to() works correctly
        let attr4 = LongAttribute::from_string_padded("hello");
        let padded = attr4.pad_to(3).unwrap();
        assert_eq!(
            padded.len(),
            3,
            "pad_to should create correct number of blocks"
        );
        let decoded4 = padded.to_string_padded().unwrap();
        assert_eq!("hello", decoded4, "pad_to should preserve original data");

        // Test 5: Various lengths with different byte patterns
        for len in 1..=32 {
            let mut data = vec![0x00; len]; // All zeros
            data[0] = 0xFF; // Make first byte non-zero

            let attr = LongAttribute::from_bytes_padded(&data);
            let decoded = attr.to_bytes_padded().unwrap();
            assert_eq!(data, decoded, "Data of length {} should work", len);
        }
    }
}
