//! External padding for batch unlinkability.
//!
//! Values of different lengths get the same structure when they are brought to a common number
//! of blocks with the `pad_to(n)` method of the long data types. This module creates and detects
//! the padding blocks. Without it, the block count of a long value would link it across a batch.
//!
//! An external padding block is 16 zero bytes, appended after the data. Encoding applies PKCS#7
//! padding to the last data block first and then adds the zero blocks. Decoding scans backwards,
//! removes zero blocks until it reaches a non-zero one, and then removes the PKCS#7 padding.
//!
//! ```text
//! After pad_to(3):
//! Block 1: [h e l l o | 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B 0x0B]  data with PKCS#7
//! Block 2: [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]  padding
//! Block 3: [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]  padding
//! ```
//!
//! The scheme is unambiguous. PKCS#7 padding leaves the last byte of a data block between `0x01`
//! and `0x10`, so a data block is never all zeros, even when the data itself is. Every byte
//! sequence can therefore be encoded and decoded.

use crate::group::Bytes;

/// Creates an external padding block: all zeros.
pub(crate) fn create_external_padding_block<B: Bytes>() -> B {
    B::zeroed()
}

/// Whether a block is an external padding block, that is, all zeros. A PKCS#7 padded data block
/// always ends in `0x01` to `0x10`, so it is never mistaken for one.
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
