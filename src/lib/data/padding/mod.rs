//! Padding of data to blocks.
//!
//! Two kinds of padding exist:
//!
//! - **Internal padding** ([`internal`]): PKCS#7 padding inside a block, so that any byte string
//!   up to one byte short of a block fits in a block, and the last block of a long value marks
//!   where the data ends.
//! - **External padding** ([`external`], `long` feature): all-zero blocks appended to a long
//!   value to bring it to a given number of blocks, so that values in a batch share one
//!   structure.
//!
//! Both are unambiguous: PKCS#7 padding never ends a block with a zero byte, so an all-zero
//! block is always external padding.

pub mod internal;

#[cfg(feature = "long")]
pub mod external;

pub use internal::Padded;

use thiserror::Error;

/// An error in the padding or unpadding of a value.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaddingError {
    /// The data does not leave room for at least one padding byte.
    #[error("{len} bytes of data do not fit in a block of {block} bytes with padding")]
    TooLong {
        /// The length of the data.
        len: usize,
        /// The length of a block.
        block: usize,
    },
    /// The value was not produced by the invertible (lizard) encoding, so it holds no block.
    #[error("the value is not an encoded block")]
    NotEncoded,
    /// The block does not end in valid PKCS#7 padding.
    #[error("invalid PKCS#7 padding")]
    InvalidPadding,
    /// A long value without blocks cannot be decoded.
    #[error("the value has no blocks")]
    Empty,
    /// A long value cannot be padded to fewer blocks than it has.
    #[error("cannot pad {current} blocks to {target}")]
    TooManyBlocks {
        /// The number of blocks the value has.
        current: usize,
        /// The number of blocks asked for.
        target: usize,
    },
    /// The decoded bytes are not valid UTF-8.
    #[error("the decoded bytes are not valid UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
}
