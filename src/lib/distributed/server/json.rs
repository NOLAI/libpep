//! JSON operations for distributed PEP systems.

use crate::core::json::core::EncryptedPEPJSONValue;
use crate::core::transcryption::contexts::TranscryptionInfo;
use crate::distributed::server::core::PEPSystem;
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
        encrypted.transcrypt(transcryption_info)
    }

    #[cfg(feature = "batch")]
    /// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
    ///
    /// This is useful for unlinkability - the shuffled order prevents correlation
    /// between input and output based on position.
    pub fn transcrypt_json_batch<R: RngCore + CryptoRng>(
        &self,
        values: Vec<EncryptedPEPJSONValue>,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Vec<EncryptedPEPJSONValue> {
        crate::core::json::transcryption::transcrypt_batch(values, transcryption_info, rng)
    }
}

#[cfg(feature = "python")]
pub mod py {
    //! Python bindings for distributed server JSON operations.
    //!
    //! The JSON methods for PyPEPSystem are implemented directly in
    //! `distributed::server::py::core` to avoid conflicting #[pymethods] implementations.

    use pyo3::prelude::*;

    pub fn register(_m: &Bound<'_, PyModule>) -> PyResult<()> {
        // Methods are added to PyPEPSystem in core.rs
        Ok(())
    }
}

#[cfg(feature = "wasm")]
pub mod wasm {
    //! WASM bindings for distributed server JSON operations.
    //!
    //! The JSON methods for WASMPEPSystem are implemented directly in
    //! `distributed::server::wasm::core` to avoid multiple #[wasm_bindgen] implementations.
}
