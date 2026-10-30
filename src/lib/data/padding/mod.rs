//! Padding of data to blocks.
//!
//! Two kinds of padding exist:
//!
//! - **Internal padding** ([`internal`]): PKCS#7 padding inside a block, so that any byte string
//!   up to one byte short of a block fits in a block, and the last block of a long value marks
//!   where the data ends.
//! - **External padding** (`external`, `long` feature): all-zero blocks appended to a long
//!   value to bring it to a given number of blocks, so that values in a batch share one
//!   structure.
//!
//! Both are unambiguous: PKCS#7 padding never ends a block with a zero byte, so an all-zero
//! block is always external padding.

pub mod internal;

#[cfg(feature = "long")]
pub mod external;

pub use internal::Padded;
mod error;

pub use error::PaddingError;
