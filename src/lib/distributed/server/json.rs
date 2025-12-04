//! JSON operations for distributed PEP systems.

use crate::core::json::data::EncryptedPEPJSONValue;
use crate::core::transcryption::contexts::TranscryptionInfo;
use crate::distributed::server::transcryptor::PEPSystem;
use rand_core::{CryptoRng, RngCore};

impl PEPSystem {
    /// Transcrypt an EncryptedPEPJSONValue from one context to another.
    ///
    /// This transcrypts all encrypted attributes and pseudonyms in the value,
    /// applying both rekeying (for attributes) and pseudonymization (for pseudonyms).
    pub fn transcrypt_json(
        &self,
        encrypted: &EncryptedPEPJSONValue,
        transcryption_info: &TranscryptionInfo,
    ) -> EncryptedPEPJSONValue {
        crate::core::json::transcryption::transcrypt_json(encrypted, transcryption_info)
    }

    #[cfg(feature = "batch")]
    /// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
    ///
    /// This is useful for unlinkability - the shuffled order prevents correlation
    /// between input and output based on position.
    ///
    /// # Errors
    ///
    /// Returns an error if the values do not all have the same structure.
    pub fn transcrypt_json_batch<R: RngCore + CryptoRng>(
        &self,
        values: Vec<EncryptedPEPJSONValue>,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Vec<EncryptedPEPJSONValue>, String> {
        crate::core::json::transcryption::transcrypt_json_batch(values, transcryption_info, rng)
    }
}
