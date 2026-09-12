//! Error types shared across the library.

#[cfg(feature = "json")]
use crate::data::json::{JsonError, UnifyError};
use thiserror::Error;

/// Error type for batch operation failures.
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
        index: usize,
        expected_structure: String,
        actual_structure: String,
    },
    /// Decryption of an item in the batch failed because the secret key does not match.
    ///
    /// Only occurs with the `elgamal3` feature, where ciphertexts encode the public key they
    /// were encrypted for and decryption with a mismatched key is detected.
    #[error("Decryption failed for entry at index {index}.")]
    DecryptionFailed { index: usize },
    #[cfg(feature = "json")]
    #[error(transparent)]
    UnifyError(#[from] UnifyError),
    #[cfg(feature = "json")]
    #[error(transparent)]
    JsonError(#[from] JsonError),
}
