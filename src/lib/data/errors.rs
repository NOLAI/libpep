//! The error of the string encodings of long values and records.

use thiserror::Error;

/// An error in parsing the string encoding of a long encrypted value or an encrypted record.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// A part of the string is not a base64-encoded ciphertext.
    #[error("invalid base64-encoded ciphertext: {0}")]
    InvalidCiphertext(String),
    /// The pseudonyms and attributes of a record are not separated by `;`.
    #[error("expected pseudonyms and attributes separated by ';'")]
    MissingSeparator,
    /// A part of a long record does not start with the number of its values, or has a different
    /// number of values than it states.
    #[cfg(feature = "long")]
    #[error("expected the number of values before ':', matching the values: {0}")]
    InvalidCount(String),
}
