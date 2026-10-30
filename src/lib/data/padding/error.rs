//! The error of the padded encodings.

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
    #[cfg(feature = "long")]
    #[error("the value has no blocks")]
    Empty,
    /// A long value cannot be padded to fewer blocks than it has.
    #[cfg(feature = "long")]
    #[error("cannot pad {current} blocks to {target}")]
    TooManyBlocks {
        /// The number of blocks the value has.
        current: usize,
        /// The number of blocks asked for.
        target: usize,
    },
    /// A record has a different number of values than the structure it is padded to.
    #[cfg(feature = "long")]
    #[error("the record has {current} values where the structure has {target}")]
    CountMismatch {
        /// The number of values the record has.
        current: usize,
        /// The number of values in the structure.
        target: usize,
    },
    /// The decoded bytes are not valid UTF-8.
    #[error("the decoded bytes are not valid UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
}
