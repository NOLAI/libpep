//! WASM bindings for verifiable JSON transcryption.
//!
//! Wraps [`JSONTranscryptionProof`] and [`VerifiableJSONBatch`], and adds a
//! `verifiableTranscrypt` producer on the existing
//! [`WASMEncryptedPEPJSONValue`].
//!
//! Verifier-side methods `verifyJSONTranscryption` /
//! `verifyJSONTranscryptionBatch` are added to `WASMVerifier` from this module
//! via an extra `#[wasm_bindgen(js_class = Verifier)]` impl block.

use crate::data::verifiable::json::JSONTranscryptionProof;
#[cfg(all(feature = "batch", feature = "verifiable"))]
use crate::data::verifiable::json::VerifiableJSONBatch;
use crate::data::wasm::json::WASMEncryptedPEPJSONValue;
use crate::factors::wasm::commitments::WASMVerifiableTranscryptionCommitment;
use crate::factors::wasm::contexts::WASMTranscryptionInfo;
use crate::verifier::wasm::WASMVerifier;
use wasm_bindgen::prelude::*;

fn verify_err() -> JsValue {
    JsValue::from(JsError::new("verification failed"))
}

// ---------------------------------------------------------------------------
// JSONTranscryptionProof
// ---------------------------------------------------------------------------

/// Proof for verifiable transcryption of an `EncryptedPEPJSONValue`.
#[wasm_bindgen(js_name = JSONTranscryptionProof)]
#[derive(Clone)]
pub struct WASMJSONTranscryptionProof(pub(crate) JSONTranscryptionProof);

impl From<JSONTranscryptionProof> for WASMJSONTranscryptionProof {
    fn from(p: JSONTranscryptionProof) -> Self {
        Self(p)
    }
}

impl From<WASMJSONTranscryptionProof> for JSONTranscryptionProof {
    fn from(p: WASMJSONTranscryptionProof) -> Self {
        p.0
    }
}

#[wasm_bindgen(js_class = JSONTranscryptionProof)]
impl WASMJSONTranscryptionProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMJSONTranscryptionProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMJSONTranscryptionProof)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    /// Verify the proof against the original encrypted JSON value and the
    /// published transition commitments. Returns `true` on success.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen]
    pub fn verify(
        &self,
        original: &WASMEncryptedPEPJSONValue,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> bool {
        self.0.verify(&original.0, &commitments.0)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen]
    pub fn verify(
        &self,
        original: &WASMEncryptedPEPJSONValue,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> bool {
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        self.0.verify(&original.0, &keys, &commitments.0)
    }

    /// Verify and reconstruct the transcrypted JSON value.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMEncryptedPEPJSONValue,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPEPJSONValue, JsValue> {
        self.0
            .verified_reconstruct(&original.0, &commitments.0)
            .map(WASMEncryptedPEPJSONValue)
            .ok_or_else(verify_err)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMEncryptedPEPJSONValue,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPEPJSONValue, JsValue> {
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        self.0
            .verified_reconstruct(&original.0, &keys, &commitments.0)
            .map(WASMEncryptedPEPJSONValue)
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// VerifiableJSONBatch
// ---------------------------------------------------------------------------

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[wasm_bindgen(js_name = VerifiableJSONBatch)]
#[derive(Clone)]
pub struct WASMVerifiableJSONBatch(pub(crate) VerifiableJSONBatch);

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<VerifiableJSONBatch> for WASMVerifiableJSONBatch {
    fn from(b: VerifiableJSONBatch) -> Self {
        Self(b)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<WASMVerifiableJSONBatch> for VerifiableJSONBatch {
    fn from(b: WASMVerifiableJSONBatch) -> Self {
        b.0
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[wasm_bindgen(js_class = VerifiableJSONBatch)]
impl WASMVerifiableJSONBatch {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableJSONBatch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableJSONBatch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

// ---------------------------------------------------------------------------
// Producer: WASMEncryptedPEPJSONValue.verifiableTranscrypt
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_class = EncryptedPEPJSONValue)]
impl WASMEncryptedPEPJSONValue {
    /// Produce a verifiable transcryption proof for this encrypted JSON
    /// value. Pass the proof together with the original ciphertext to a
    /// verifier to obtain the reconstructed value.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn wasm_verifiable_transcrypt(
        &self,
        info: &WASMTranscryptionInfo,
    ) -> WASMJSONTranscryptionProof {
        use crate::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        WASMJSONTranscryptionProof(self.0.verifiable_transcrypt(&info.0, &mut rng))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn wasm_verifiable_transcrypt(
        &self,
        info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> WASMJSONTranscryptionProof {
        use crate::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        WASMJSONTranscryptionProof(self.0.verifiable_transcrypt(&info.0, &keys, &mut rng))
    }
}

// ---------------------------------------------------------------------------
// Verifier methods: verifyJSONTranscryption(_Batch)
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_class = Verifier)]
impl WASMVerifier {
    /// Verify a JSON transcryption proof, returning the reconstructed
    /// encrypted JSON value on success.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifyJSONTranscryption)]
    pub fn verify_json_transcryption(
        &self,
        original: &WASMEncryptedPEPJSONValue,
        proof: &WASMJSONTranscryptionProof,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPEPJSONValue, JsValue> {
        self.inner
            .verified_reconstruct_transcryption(&original.0, &proof.0, &commitments.0)
            .map(WASMEncryptedPEPJSONValue)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyJSONTranscryption)]
    pub fn verify_json_transcryption(
        &self,
        original: &WASMEncryptedPEPJSONValue,
        proof: &WASMJSONTranscryptionProof,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPEPJSONValue, JsValue> {
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .verified_reconstruct_transcryption(&original.0, &proof.0, &keys, &commitments.0)
            .map(WASMEncryptedPEPJSONValue)
            .map_err(crate::wasm_errors::verify_err_to_js)
    }
}
