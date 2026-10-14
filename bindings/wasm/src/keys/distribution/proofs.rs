//! WASM bindings for session-key-share zero-knowledge proofs.
//!
//! Mirrors `libpep::keys::distribution::proofs`; available with `feature = "verifiable"`.

#![cfg(feature = "verifiable")]

use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::arithmetic::scalars::WASMScalarNonZero;
use crate::errors::malformed_proof_err;
use crate::keys::distribution::shares::{
    WASMAttributeSessionKeyShare, WASMPseudonymSessionKeyShare,
};
use derive_more::{From, Into};
use libpep::keys::distribution::{BlindingCommitment, SessionKeyShareProof};
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
        Self(libpep::keys::distribution::proofs::generic::BlindingCommitment(point.0))
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
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMBlindingCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMBlindingCommitment)
            .map_err(malformed_proof_err)
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

    /// Verify the proof *and* bind it to the pseudonym share actually received.
    ///
    /// This is the check a user accepting a session-key share must perform: it
    /// verifies the proof and additionally checks `U_i == u_i · G` for the
    /// share handed over alongside it. Without the second half, a transcryptor
    /// can pair a valid proof with an unrelated scalar.
    #[wasm_bindgen(js_name = verifyPseudonymShare)]
    pub fn verify_pseudonym_share(
        &self,
        share: &WASMPseudonymSessionKeyShare,
        blinding_commitment: &WASMBlindingCommitment,
        rekey_commitment: &WASMGroupElement,
    ) -> bool {
        self.0
            .verify_share(&share.0, &blinding_commitment.0, &rekey_commitment.0)
    }

    /// Verify the proof *and* bind it to the attribute share actually received.
    ///
    /// See [`verifyPseudonymShare`](Self::verify_pseudonym_share); this is the
    /// same check for an attribute share.
    #[wasm_bindgen(js_name = verifyAttributeShare)]
    pub fn verify_attribute_share(
        &self,
        share: &WASMAttributeSessionKeyShare,
        blinding_commitment: &WASMBlindingCommitment,
        rekey_commitment: &WASMGroupElement,
    ) -> bool {
        self.0
            .verify_share(&share.0, &blinding_commitment.0, &rekey_commitment.0)
    }

    /// Verify the proof against a blinding commitment and rekey commitment.
    ///
    /// This does NOT establish that any particular share is correct: it never
    /// sees the share scalar. A user accepting a share must use
    /// `verifyPseudonymShare` or `verifyAttributeShare` instead.
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
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    /// Deserialize from JSON.
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMSessionKeyShareProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMSessionKeyShareProof)
            .map_err(malformed_proof_err)
    }
}
