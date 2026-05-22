//! External padding for batch unlinkability.
//!
//! This module provides functions to create and detect external padding blocks used by the
//! `pad_to()` method on long data types for batch unlinkability.
//!
//! # Purpose
//!
//! External padding normalizes different-sized values to identical structure for unlinkable batch transcryption.
//!
//! # When Used
//!
//! - Explicitly via the `pad_to(n)` method on long types
//! - Only for multi-block data (see [`long`](crate::data::long) module)
//! - Required when batch processing needs unlinkability guarantees
//!
//! # How It Works
//!
//! - Adds full 16-byte all-zero blocks after the data
//! - Format: `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`
//! - During decoding, scans backwards from the end removing all-zero blocks until a data block is found
//! - Automatically detected and removed during decoding
//!
//! # Order of Operations
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
//! This ordering ensures that even if data is all zeros, PKCS#7 padding will change the last
//! byte to `0x01`-`0x10`, guaranteeing it won't be detected as an external padding block.
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
//! # Disambiguation Guarantee
//!
//! External padding blocks are **all zeros**, while PKCS#7 padded blocks **never** have `0x00`
//! in the last byte (valid PKCS#7 padding: `0x01`-`0x10`).
//!
//! Because PKCS#7 padding is applied first during encoding, it **always** changes the last
//! byte of any data block to `0x01`-`0x10`. This deterministically prevents any data from being
//! mistaken for an external padding block.
//!
//! This means **ALL possible byte sequences can be encoded without ambiguity**, including values
//! that are all zeros (PKCS#7 changes the last byte)

/// Creates an external padding block.
///
/// Format: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
///
/// All-zero blocks are impossible for PKCS#7 padded data blocks (valid padding bytes are 0x01-0x10),
/// making this unambiguous.
pub(crate) fn create_external_padding_block() -> [u8; 16] {
    [0u8; 16]
}

/// Checks if a block is an external padding block.
///
/// Returns `true` if this block is all zeros (external padding),
/// or `false` if this is a regular data block.
///
/// # Disambiguation Guarantee
///
/// - External padding blocks are **all zeros**
/// - PKCS#7 padded data blocks **never** have `0x00` in the last byte (valid padding: `0x01`-`0x10`)
///
/// This means **ALL possible byte sequences can be encoded without ambiguity**, including:
/// - Data blocks that are all zeros except the last byte (PKCS#7 will set last byte to 0x01-0x10)
/// - Any combination of bytes whatsoever
pub(crate) fn is_external_padding_block(block: &[u8]) -> bool {
    if block.len() != 16 {
        return false;
    }

    // Check if the entire block is all zeros
    // This guarantees disambiguation from data blocks because PKCS#7 padding
    // always changes the last byte to 0x01-0x10, never 0x00
    block.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_external_padding_block() {
        let block = create_external_padding_block();

        // Check that the entire block is all zeros
        assert_eq!(&block, &[0u8; 16]);
    }

    #[test]
    fn test_is_external_padding_block_valid() {
        let block = create_external_padding_block();
        assert!(is_external_padding_block(&block));
    }

    #[test]
    fn test_is_external_padding_block_invalid_length() {
        let block = [0x00; 4];
        assert!(!is_external_padding_block(&block));
    }

    #[test]
    fn test_is_external_padding_block_not_all_zeros() {
        let mut block = [0x00; 16];
        block[0] = 0xFF; // Not all zeros
        assert!(!is_external_padding_block(&block));
    }

    #[test]
    fn test_disambiguation_pkcs7_never_all_zeros() {
        // PKCS#7 valid padding bytes are 0x01-0x10
        // External padding is all zeros
        // This guarantees no ambiguity

        for padding_value in 0x01..=0x10u8 {
            let pkcs7_block = [padding_value; 16];
            // PKCS#7 block is not all zeros
            assert!(!is_external_padding_block(&pkcs7_block));
        }
    }
}
