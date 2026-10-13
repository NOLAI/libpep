//! Error types shared across the library.

#[cfg(feature = "json")]
use crate::data::json::{JsonError, UnifyError};
use thiserror::Error;

/// An error in a batch operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BatchError {
    /// Items in the batch have inconsistent structures.
    ///
    /// All items in a batch must have the same structure to prevent linkability.
    /// If items had different structures (e.g., different numbers of blocks in long values,
    /// different JSON shapes, or different numbers of pseudonyms/attributes in records),
    /// an attacker could potentially link items across batches based on their structure,
    /// defeating the privacy protection provided by shuffling.
    #[error("Inconsistent structure in batch. Entry at index {index} has structure {actual_structure}, expected {expected_structure}.")]
    InconsistentStructure {
        /// The index of the first item whose structure differs.
        index: usize,
        /// The structure of the first item.
        expected_structure: String,
        /// The structure of the item at `index`.
        actual_structure: String,
    },
    /// Decryption of an item in the batch failed because the secret key does not match.
    ///
    /// Only occurs with the `elgamal3` feature, where ciphertexts encode the public key they
    /// were encrypted for and decryption with a mismatched key is detected.
    #[error("Decryption failed for entry at index {index}.")]
    DecryptionFailed {
        /// The index of the item that failed to decrypt.
        index: usize,
    },
    /// The JSON values in the batch cannot be brought to one structure.
    #[cfg(feature = "json")]
    #[error(transparent)]
    UnifyError(#[from] UnifyError),
    /// A JSON value in the batch is malformed.
    #[cfg(feature = "json")]
    #[error(transparent)]
    JsonError(#[from] JsonError),
}

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
}
