//! WASM bindings for commitment types.

use crate::factors::{
    ProvedPseudonymizationCommitments, ProvedRekeyCommitments, ProvedReshuffleCommitments,
};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// Pseudonymization factor commitments with proofs (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = ProvedPseudonymizationCommitments)]
pub struct WASMProvedPseudonymizationCommitments(pub(crate) ProvedPseudonymizationCommitments);

#[wasm_bindgen(js_class = ProvedPseudonymizationCommitments)]
impl WASMProvedPseudonymizationCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMProvedPseudonymizationCommitments, JsValue> {
        serde_json::from_str(json)
            .map(WASMProvedPseudonymizationCommitments)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Reshuffle factor commitments with proof (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = ProvedReshuffleCommitments)]
pub struct WASMProvedReshuffleCommitments(pub(crate) ProvedReshuffleCommitments);

#[wasm_bindgen(js_class = ProvedReshuffleCommitments)]
impl WASMProvedReshuffleCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMProvedReshuffleCommitments, JsValue> {
        serde_json::from_str(json)
            .map(WASMProvedReshuffleCommitments)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Rekey factor commitments with proof (WASM).
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = ProvedRekeyCommitments)]
pub struct WASMProvedRekeyCommitments(pub(crate) ProvedRekeyCommitments);

#[wasm_bindgen(js_class = ProvedRekeyCommitments)]
impl WASMProvedRekeyCommitments {
    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMProvedRekeyCommitments, JsValue> {
        serde_json::from_str(json)
            .map(WASMProvedRekeyCommitments)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}
