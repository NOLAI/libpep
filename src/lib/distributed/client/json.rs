//! JSON operations for distributed PEP clients.

use crate::core::json::data::{EncryptedPEPJSONValue, JsonError, PEPJSONValue};
use crate::distributed::client::core::PEPClient;
use rand_core::{CryptoRng, RngCore};

impl PEPClient {
    /// Encrypt a PEPJSONValue into an EncryptedPEPJSONValue.
    ///
    /// Takes an unencrypted `PEPJSONValue` (created via `pep_json!` macro or builder)
    /// and encrypts it using the client's session keys.
    pub fn encrypt_json<R: RngCore + CryptoRng>(
        &self,
        pep_value: &PEPJSONValue,
        rng: &mut R,
    ) -> EncryptedPEPJSONValue {
        pep_value.encrypt(&self.keys, rng)
    }

    /// Decrypt an EncryptedPEPJSONValue back to a PEPJSONValue.
    pub fn decrypt_json(
        &self,
        encrypted: &EncryptedPEPJSONValue,
    ) -> Result<PEPJSONValue, JsonError> {
        encrypted.decrypt(&self.keys)
    }
}
