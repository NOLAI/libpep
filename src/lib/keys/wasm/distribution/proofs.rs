//! WASM bindings for session-key-share zero-knowledge proofs.
//!
//! Mirrors `crate::keys::py::distribution::proofs`. Only available with
//! `feature = "verifiable-derivation"`.

#![cfg(feature = "verifiable-derivation")]

use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::keys::distribution::{BlindingCommitment, BlindingCommitments, SessionKeyShareProof};
use derive_more::{From, Into};
use wasm_bindgen::prelude::*;

/// Public commitment `B_i = b_i · G` to a per-transcryptor blinding factor.
#[derive(Clone, Copy, From, Into)]
#[wasm_bindgen(js_name = BlindingCommitment)]
pub struct WASMBlindingCommitment(pub(crate) BlindingCommitment);

#[wasm_bindgen(js_class = BlindingCommitment)]
impl WASMBlindingCommitment {
    /// Create a blinding commitment from a blinding scalar.
    #[wasm_bindgen(constructor)]
    pub fn new(blinding: &WASMScalarNonZero) -> Self {
        Self(BlindingCommitment::new(&blinding.0))
    }

    /// Construct from a preexisting group element.
    #[wasm_bindgen(js_name = fromPoint)]
    pub fn from_point(point: &WASMGroupElement) -> Self {
        Self(BlindingCommitment(point.0))
    }

    /// Get the commitment value as a group element.
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> WASMGroupElement {
        WASMGroupElement(*self.0.value())
    }

    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMBlindingCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMBlindingCommitment)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Pair of blinding commitments for one transcryptor (pseudonym + attribute).
#[derive(Clone, Copy, From, Into)]
#[wasm_bindgen(js_name = BlindingCommitments)]
pub struct WASMBlindingCommitments(pub(crate) BlindingCommitments);

#[wasm_bindgen(js_class = BlindingCommitments)]
impl WASMBlindingCommitments {
    /// Create blinding commitments from pseudonym and attribute blinding scalars.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym_blinding: &WASMScalarNonZero,
        attribute_blinding: &WASMScalarNonZero,
    ) -> Self {
        Self(BlindingCommitments::new(
            &pseudonym_blinding.0,
            &attribute_blinding.0,
        ))
    }

    /// Build directly from two preconstructed commitments.
    #[wasm_bindgen(js_name = fromCommitments)]
    pub fn from_commitments(
        pseudonym: &WASMBlindingCommitment,
        attribute: &WASMBlindingCommitment,
    ) -> Self {
        Self(BlindingCommitments {
            pseudonym: pseudonym.0,
            attribute: attribute.0,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMBlindingCommitment {
        WASMBlindingCommitment(self.0.pseudonym)
    }

    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMBlindingCommitment {
        WASMBlindingCommitment(self.0.attribute)
    }

    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMBlindingCommitments, JsValue> {
        serde_json::from_str(json)
            .map(WASMBlindingCommitments)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Zero-knowledge proof that a session-key share `u_i = b_i · k_i` was
/// correctly constructed.
#[derive(Clone, Copy, From, Into)]
#[wasm_bindgen(js_name = SessionKeyShareProof)]
pub struct WASMSessionKeyShareProof(pub(crate) SessionKeyShareProof);

#[wasm_bindgen(js_class = SessionKeyShareProof)]
impl WASMSessionKeyShareProof {
    /// Create a session-key-share proof.
    #[wasm_bindgen(constructor)]
    pub fn new(blinding: &WASMScalarNonZero, rekey_commitment: &WASMGroupElement) -> Self {
        let mut rng = rand::rng();
        Self(SessionKeyShareProof::new(
            &blinding.0,
            &rekey_commitment.0,
            &mut rng,
        ))
    }

    /// Verify the proof against a blinding commitment and rekey commitment.
    #[wasm_bindgen]
    pub fn verify(
        &self,
        blinding_commitment: &WASMBlindingCommitment,
        rekey_commitment: &WASMGroupElement,
    ) -> bool {
        self.0.verify(&blinding_commitment.0, &rekey_commitment.0)
    }

    /// Return the public commitment `U_i = u_i · G` to the session-key share.
    #[wasm_bindgen(js_name = shareCommitment)]
    pub fn share_commitment(&self) -> WASMGroupElement {
        WASMGroupElement(*self.0.share_commitment())
    }

    /// Serialize to JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMSessionKeyShareProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMSessionKeyShareProof)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}
