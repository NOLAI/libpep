//! WASM bindings for commitment types.

use crate::factors::{VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// Pseudonymization factor commitments with proofs (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiablePseudonymizationCommitments)]
pub struct WASMVerifiablePseudonymizationCommitments(
    pub(crate) VerifiablePseudonymizationCommitment,
);

#[wasm_bindgen(js_class = VerifiablePseudonymizationCommitments)]
impl WASMVerifiablePseudonymizationCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiablePseudonymizationCommitments, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiablePseudonymizationCommitments)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Rekey factor commitments with proof (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRekeyCommitments)]
pub struct WASMVerifiableRekeyCommitments(pub(crate) VerifiableRekeyCommitment);

#[wasm_bindgen(js_class = VerifiableRekeyCommitments)]
impl WASMVerifiableRekeyCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRekeyCommitments, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRekeyCommitments)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}
