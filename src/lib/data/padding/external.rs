//! External padding for batch unlinkability.
//!
//! The functions here create and detect the external padding blocks added by the
//! `pad_to()` method on long data types. External padding gives values of different sizes the
//! same structure, which batch transcryption needs to stay unlinkable.
//!
//! # Usage
//!
//! - It is added explicitly with the `pad_to(n)` method on long types.
//! - It only applies to multi-block data (see the [`long`](crate::data::long) module).
//! - It is required when batch processing needs unlinkability.
//!
//! # Format
//!
//! - Full 16-byte all-zero blocks are added after the data:
//!   `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`
//! - Decoding detects and removes them automatically. It scans backwards from the end, removing
//!   all-zero blocks until it reaches a data block.
//!
//! # Order of operations
//!
//! **Encoding:**
//! 1. PKCS#7 padding is applied first to the last data block
//! 2. All-zero external padding blocks are added after
//!
//! **Decoding:**
//! 1. Scan backwards from the end, removing all-zero blocks
//! 2. Stop when a non-zero block is found (the last data block with PKCS#7 padding)
//! 3. Remove PKCS#7 padding from the last data block
//!
//! Because of this order, even data that is all zeros ends with a last byte of `0x01`-`0x10`
//! after PKCS#7 padding, so it is not detected as an external padding block.
//!
//! # Example
//!
//! ```text
//! After pad_to(3):
//! Block 1: [h e l l o | 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]  ← data with PKCS#7
//! Block 2: [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]  ← padding
//! Block 3: [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]  ← padding
//! ```
//!
//! # Disambiguation
//!
//! External padding blocks are all zeros, while PKCS#7 padded blocks never have `0x00` in the
//! last byte (valid PKCS#7 padding is `0x01`-`0x10`).
//!
//! PKCS#7 padding is applied first during encoding and always changes the last byte of the last
//! data block to `0x01`-`0x10`, so no data can be mistaken for an external padding block. Every
//! possible byte sequence can be encoded without ambiguity, including values that are all zeros.

use crate::elgamal::arithmetic::group::Bytes;

/// Creates an external padding block.
///
/// Format: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
///
/// PKCS#7 padded data blocks are never all zeros (valid padding bytes are 0x01-0x10), so the
/// block cannot be confused with data.
pub(crate) fn create_external_padding_block<B: Bytes>() -> B {
    B::zeroed()
}

/// Checks if a block is an external padding block.
///
/// Returns `true` if this block is all zeros (external padding),
/// or `false` if this is a regular data block.
///
/// # Disambiguation
///
/// External padding blocks are all zeros. PKCS#7 padded data blocks never have `0x00` in the last
/// byte (valid padding is `0x01`-`0x10`). Every possible byte sequence can therefore be encoded
/// without ambiguity, including data blocks that are all zeros except the last byte (PKCS#7 sets
/// the last byte to 0x01-0x10).
pub(crate) fn is_external_padding_block<B: Bytes>(block: &[u8]) -> bool {
    if block.len() != B::len() {
        return false;
    }

    // PKCS#7 padding always sets the last byte of a data block to 0x01-0x10, so a data block is
    // never all zeros.
    block.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_external_padding_block() {
        let block = create_external_padding_block::<[u8; 16]>();

        // Check that the entire block is all zeros
        assert_eq!(&block, &[0u8; 16]);
    }

    #[test]
    fn test_is_external_padding_block_valid() {
        let block = create_external_padding_block::<[u8; 16]>();
        assert!(is_external_padding_block::<[u8; 16]>(&block));
    }

    #[test]
    fn test_is_external_padding_block_invalid_length() {
        let block = [0x00; 4];
        assert!(!is_external_padding_block::<[u8; 16]>(&block));
    }

    #[test]
    fn test_is_external_padding_block_not_all_zeros() {
        let mut block = [0x00; 16];
        block[0] = 0xFF; // Not all zeros
        assert!(!is_external_padding_block::<[u8; 16]>(&block));
    }

    #[test]
    fn test_disambiguation_pkcs7_never_all_zeros() {
        // PKCS#7 valid padding bytes are 0x01-0x10
        // External padding is all zeros
        // This guarantees no ambiguity

        for padding_value in 0x01..=0x10u8 {
            let pkcs7_block = [padding_value; 16];
            // PKCS#7 block is not all zeros
            assert!(!is_external_padding_block::<[u8; 16]>(&pkcs7_block));
        }
    }
}
