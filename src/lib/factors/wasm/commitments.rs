//! WASM bindings for commitment types.

use crate::factors::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
use crate::wasm_errors::malformed_proof_err;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// Pseudonymization factor commitment for a single transition (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiablePseudonymizationCommitment)]
pub struct WASMVerifiablePseudonymizationCommitment(
    pub(crate) VerifiablePseudonymizationCommitment,
);

#[wasm_bindgen(js_class = VerifiablePseudonymizationCommitment)]
impl WASMVerifiablePseudonymizationCommitment {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiablePseudonymizationCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiablePseudonymizationCommitment)
            .map_err(malformed_proof_err)
    }
}

/// Rekey factor commitment for a single transition (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRekeyCommitment)]
pub struct WASMVerifiableRekeyCommitment(pub(crate) VerifiableRekeyCommitment);

#[wasm_bindgen(js_class = VerifiableRekeyCommitment)]
impl WASMVerifiableRekeyCommitment {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRekeyCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRekeyCommitment)
            .map_err(malformed_proof_err)
    }
}

/// Combined transcryption commitments — pseudonymization (reshuffle + rekey)
/// plus attribute rekey — for a transition (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableTranscryptionCommitment)]
pub struct WASMVerifiableTranscryptionCommitment(pub(crate) VerifiableTranscryptionCommitment);

#[wasm_bindgen(js_class = VerifiableTranscryptionCommitment)]
impl WASMVerifiableTranscryptionCommitment {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableTranscryptionCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableTranscryptionCommitment)
            .map_err(malformed_proof_err)
    }
}
