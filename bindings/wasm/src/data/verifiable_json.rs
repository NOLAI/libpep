//! WASM bindings for verifiable JSON transcryption.
//!
//! Wraps [`JsonTranscryptionProof`] and [`JsonTranscryptionBatchProof`], and adds a
//! `verifiableTranscrypt` producer on the existing
//! [`WASMEncryptedPepJsonValue`].
//!
//! Verifier-side methods `verifyJSONTranscryption` /
//! `verifyJSONTranscryptionBatch` are added to `WASMVerifier` from this module
//! via an extra `#[wasm_bindgen(js_class = Verifier)]` impl block.

use crate::data::json::WASMEncryptedPepJsonValue;
use crate::errors::{malformed_proof_err, verify_err_to_js};
use crate::factors::commitments::WASMVerifiableTranscryptionCommitment;
use crate::factors::types::WASMTranscryptionInfo;
use crate::verifier::WASMVerifier;
#[cfg(all(feature = "batch", feature = "verifiable"))]
use libpep::data::verifiable::json::JsonTranscryptionBatchProof;
use libpep::data::verifiable::json::JsonTranscryptionProof;
use libpep::data::verifiable::traits::VerifiableTranscryptionProof;
use libpep::verifier::VerifyError;
use wasm_bindgen::prelude::*;

fn verify_err() -> JsValue {
    verify_err_to_js(VerifyError::ProofRejected)
}

// ---------------------------------------------------------------------------
// JsonTranscryptionProof
// ---------------------------------------------------------------------------

/// Proof for verifiable transcryption of an `EncryptedPepJsonValue`.
#[wasm_bindgen(js_name = JsonTranscryptionProof)]
#[derive(Clone)]
pub struct WASMJsonTranscryptionProof(pub(crate) JsonTranscryptionProof);

impl From<JsonTranscryptionProof> for WASMJsonTranscryptionProof {
    fn from(p: JsonTranscryptionProof) -> Self {
        Self(p)
    }
}

impl From<WASMJsonTranscryptionProof> for JsonTranscryptionProof {
    fn from(p: WASMJsonTranscryptionProof) -> Self {
        p.0
    }
}

#[wasm_bindgen(js_class = JsonTranscryptionProof)]
impl WASMJsonTranscryptionProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMJsonTranscryptionProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMJsonTranscryptionProof)
            .map_err(malformed_proof_err)
    }

    /// Verify the proof against the original encrypted JSON value and the
    /// published transition commitments. Returns `true` on success.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen]
    pub fn verify(
        &self,
        original: &WASMEncryptedPepJsonValue,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> bool {
        self.0.verify(&original.0, &commitments.0)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen]
    pub fn verify(
        &self,
        original: &WASMEncryptedPepJsonValue,
        session_keys: &crate::keys::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> bool {
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        self.0.verify(&original.0, &keys.public(), &commitments.0)
    }

    /// Verify and reconstruct the transcrypted JSON value.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMEncryptedPepJsonValue,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPepJsonValue, JsValue> {
        self.0
            .verified_reconstruct(&original.0, &commitments.0)
            .map(WASMEncryptedPepJsonValue)
            .ok_or_else(verify_err)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMEncryptedPepJsonValue,
        session_keys: &crate::keys::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPepJsonValue, JsValue> {
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        self.0
            .verified_reconstruct(&original.0, &keys.public(), &commitments.0)
            .map(WASMEncryptedPepJsonValue)
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// JsonTranscryptionBatchProof
// ---------------------------------------------------------------------------

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[wasm_bindgen(js_name = JsonTranscryptionBatchProof)]
#[derive(Clone)]
pub struct WASMJsonTranscryptionBatchProof(pub(crate) JsonTranscryptionBatchProof);

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<JsonTranscryptionBatchProof> for WASMJsonTranscryptionBatchProof {
    fn from(b: JsonTranscryptionBatchProof) -> Self {
        Self(b)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl From<WASMJsonTranscryptionBatchProof> for JsonTranscryptionBatchProof {
    fn from(b: WASMJsonTranscryptionBatchProof) -> Self {
        b.0
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
#[wasm_bindgen(js_class = JsonTranscryptionBatchProof)]
impl WASMJsonTranscryptionBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMJsonTranscryptionBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMJsonTranscryptionBatchProof)
            .map_err(malformed_proof_err)
    }
}

// ---------------------------------------------------------------------------
// Producer: WASMEncryptedPepJsonValue.verifiableTranscrypt
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_class = EncryptedPepJsonValue)]
impl WASMEncryptedPepJsonValue {
    /// Produce a verifiable transcryption proof for this encrypted JSON
    /// value. Pass the proof together with the original ciphertext to a
    /// verifier to obtain the reconstructed value.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn wasm_verifiable_transcrypt(
        &self,
        info: &WASMTranscryptionInfo,
    ) -> WASMJsonTranscryptionProof {
        use libpep::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        WASMJsonTranscryptionProof(self.0.verifiable_transcrypt(&info.0, &mut rng))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn wasm_verifiable_transcrypt(
        &self,
        info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> WASMJsonTranscryptionProof {
        use libpep::data::verifiable::traits::VerifiableTranscryptable;
        let mut rng = rand::rng();
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        WASMJsonTranscryptionProof(
            self.0
                .verifiable_transcrypt(&info.0, &keys.public(), &mut rng),
        )
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
    #[wasm_bindgen(js_name = verifyJsonTranscryption)]
    pub fn verify_json_transcryption(
        &self,
        original: &WASMEncryptedPepJsonValue,
        proof: &WASMJsonTranscryptionProof,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPepJsonValue, JsValue> {
        self.inner
            .verified_reconstruct_transcryption(&original.0, &proof.0, &commitments.0)
            .map(WASMEncryptedPepJsonValue)
            .map_err(crate::errors::verify_err_to_js)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifyJsonTranscryption)]
    pub fn verify_json_transcryption(
        &self,
        original: &WASMEncryptedPepJsonValue,
        proof: &WASMJsonTranscryptionProof,
        session_keys: &crate::keys::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedPepJsonValue, JsValue> {
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        self.inner
            .verified_reconstruct_transcryption(
                &original.0,
                &proof.0,
                &keys.public(),
                &commitments.0,
            )
            .map(WASMEncryptedPepJsonValue)
            .map_err(crate::errors::verify_err_to_js)
    }
}
