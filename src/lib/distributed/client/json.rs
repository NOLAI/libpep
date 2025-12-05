//! JSON operations for distributed PEP clients.

use crate::core::json::data::{
    decrypt_json, encrypt_json, EncryptedPEPJSONValue, JsonError, PEPJSONValue,
};
use crate::distributed::client::client::PEPClient;
use rand_core::{CryptoRng, RngCore};

impl PEPClient {
    /// Encrypt a PEPJSONValue into an EncryptedPEPJSONValue.
    ///
    /// Takes an unencrypted `PEPJSONValue` (created via `pep_json!` macro or builder)
    /// and encrypts it using the client's session keys.
    pub fn encrypt_json_value<R: RngCore + CryptoRng>(
        &self,
        pep_value: &PEPJSONValue,
        rng: &mut R,
    ) -> EncryptedPEPJSONValue {
        encrypt_json(pep_value, &self.keys, rng)
    }

    /// Decrypt an EncryptedPEPJSONValue back to a PEPJSONValue.
    pub fn decrypt_json_value(
        &self,
        encrypted: &EncryptedPEPJSONValue,
    ) -> Result<PEPJSONValue, JsonError> {
        decrypt_json(encrypted, &self.keys)
    }
}
