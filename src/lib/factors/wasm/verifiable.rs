//! WASM bindings for verifiable Carter-Wegman factor derivation.
//!
//! Mirrors `crate::factors::verifiable`. Only available with
//! `feature = "verifiable-derivation"`.

#![cfg(feature = "verifiable-derivation")]

use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::factors::verifiable::{
    MasterPseudonymizationPublicKey, MasterPseudonymizationSecret, MasterRekeyingPublicKey,
    MasterRekeyingSecret,
};
use crate::factors::wasm::contexts::{WASMEncryptionContext, WASMPseudonymizationDomain};
use derive_more::{From, Into};
use wasm_bindgen::prelude::*;

/// Master pseudonymization secret with two Carter-Wegman components.
#[derive(Clone, From, Into)]
#[wasm_bindgen(js_name = MasterPseudonymizationSecret)]
pub struct WASMMasterPseudonymizationSecret(pub(crate) MasterPseudonymizationSecret);

#[wasm_bindgen(js_class = MasterPseudonymizationSecret)]
impl WASMMasterPseudonymizationSecret {
    /// Generate a new random master pseudonymization secret.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self(MasterPseudonymizationSecret::random(&mut rng))
    }

    /// Generate a new random master pseudonymization secret.
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::rng();
        Self(MasterPseudonymizationSecret::random(&mut rng))
    }

    /// Derive the public key for this secret.
    #[wasm_bindgen(js_name = toPublicKey)]
    pub fn to_public_key(&self) -> WASMMasterPseudonymizationPublicKey {
        WASMMasterPseudonymizationPublicKey(self.0.public_key())
    }

    /// Derive a reshuffling factor for a domain.
    #[wasm_bindgen(js_name = deriveReshuffleFactor)]
    pub fn derive_reshuffle_factor(
        &self,
        domain: &WASMPseudonymizationDomain,
    ) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0.derive_reshuffle_factor(&domain.0))
    }
}

impl Default for WASMMasterPseudonymizationSecret {
    fn default() -> Self {
        Self::new()
    }
}

/// Master pseudonymization public key `(X₁, X₂)`.
#[derive(Clone, Copy, From, Into)]
#[wasm_bindgen(js_name = MasterPseudonymizationPublicKey)]
pub struct WASMMasterPseudonymizationPublicKey(pub(crate) MasterPseudonymizationPublicKey);

#[wasm_bindgen(js_class = MasterPseudonymizationPublicKey)]
impl WASMMasterPseudonymizationPublicKey {
    /// Construct from two group elements `X₁` and `X₂`.
    #[wasm_bindgen(constructor)]
    pub fn new(x1: &WASMGroupElement, x2: &WASMGroupElement) -> Self {
        Self(MasterPseudonymizationPublicKey { x1: x1.0, x2: x2.0 })
    }

    #[wasm_bindgen(getter)]
    pub fn x1(&self) -> WASMGroupElement {
        WASMGroupElement(self.0.x1)
    }

    #[wasm_bindgen(getter)]
    pub fn x2(&self) -> WASMGroupElement {
        WASMGroupElement(self.0.x2)
    }

    /// Compute the reshuffle factor commitment `S_d = s_d·G` for a domain.
    #[wasm_bindgen(js_name = computeReshuffleCommitment)]
    pub fn compute_reshuffle_commitment(
        &self,
        domain: &WASMPseudonymizationDomain,
    ) -> WASMGroupElement {
        WASMGroupElement(self.0.compute_reshuffle_commitment(&domain.0))
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
    pub fn from_json(json: &str) -> Result<WASMMasterPseudonymizationPublicKey, JsValue> {
        serde_json::from_str(json)
            .map(WASMMasterPseudonymizationPublicKey)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Master rekeying secret with two Carter-Wegman components.
#[derive(Clone, From, Into)]
#[wasm_bindgen(js_name = MasterRekeyingSecret)]
pub struct WASMMasterRekeyingSecret(pub(crate) MasterRekeyingSecret);

#[wasm_bindgen(js_class = MasterRekeyingSecret)]
impl WASMMasterRekeyingSecret {
    /// Generate a new random master rekeying secret.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self(MasterRekeyingSecret::random(&mut rng))
    }

    /// Generate a new random master rekeying secret.
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::rng();
        Self(MasterRekeyingSecret::random(&mut rng))
    }

    /// Derive the public key for this secret.
    #[wasm_bindgen(js_name = toPublicKey)]
    pub fn to_public_key(&self) -> WASMMasterRekeyingPublicKey {
        WASMMasterRekeyingPublicKey(self.0.public_key())
    }

    /// Derive a pseudonym rekeying factor for a context.
    #[wasm_bindgen(js_name = derivePseudonymRekey)]
    pub fn derive_pseudonym_rekey(&self, context: &WASMEncryptionContext) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0.derive_pseudonym_rekey_factor(&context.0))
    }

    /// Derive an attribute rekeying factor for a context.
    #[wasm_bindgen(js_name = deriveAttributeRekey)]
    pub fn derive_attribute_rekey(&self, context: &WASMEncryptionContext) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0.derive_attribute_rekey_factor(&context.0))
    }
}

impl Default for WASMMasterRekeyingSecret {
    fn default() -> Self {
        Self::new()
    }
}

/// Master rekeying public key `(Y₁, Y₂)`.
#[derive(Clone, Copy, From, Into)]
#[wasm_bindgen(js_name = MasterRekeyingPublicKey)]
pub struct WASMMasterRekeyingPublicKey(pub(crate) MasterRekeyingPublicKey);

#[wasm_bindgen(js_class = MasterRekeyingPublicKey)]
impl WASMMasterRekeyingPublicKey {
    /// Construct from two group elements `Y₁` and `Y₂`.
    #[wasm_bindgen(constructor)]
    pub fn new(y1: &WASMGroupElement, y2: &WASMGroupElement) -> Self {
        Self(MasterRekeyingPublicKey { y1: y1.0, y2: y2.0 })
    }

    #[wasm_bindgen(getter)]
    pub fn y1(&self) -> WASMGroupElement {
        WASMGroupElement(self.0.y1)
    }

    #[wasm_bindgen(getter)]
    pub fn y2(&self) -> WASMGroupElement {
        WASMGroupElement(self.0.y2)
    }

    /// Compute the pseudonym rekey factor commitment `K_s = k_s·G` for a context.
    #[wasm_bindgen(js_name = computePseudonymRekeyCommitment)]
    pub fn compute_pseudonym_rekey_commitment(
        &self,
        context: &WASMEncryptionContext,
    ) -> WASMGroupElement {
        WASMGroupElement(self.0.compute_pseudonym_rekey_commitment(&context.0))
    }

    /// Compute the attribute rekey factor commitment for a context.
    #[wasm_bindgen(js_name = computeAttributeRekeyCommitment)]
    pub fn compute_attribute_rekey_commitment(
        &self,
        context: &WASMEncryptionContext,
    ) -> WASMGroupElement {
        WASMGroupElement(self.0.compute_attribute_rekey_commitment(&context.0))
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
    pub fn from_json(json: &str) -> Result<WASMMasterRekeyingPublicKey, JsValue> {
        serde_json::from_str(json)
            .map(WASMMasterRekeyingPublicKey)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}
