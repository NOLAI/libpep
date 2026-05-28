//! WASM bindings for the verifiable batch flow.
//!
//! Wraps the eight batch-proof types from
//! [`crate::data::verifiable`] and exposes `verifiedReconstructBatch`
//! on each. Cfg-forks mirror Rust 1:1: `(batch-pk, !elgamal3)` takes both
//! the old and new recipient key, `(!batch-pk, !elgamal3)` takes only the
//! recipient key, and `elgamal3` takes neither.
//!
//! This module also adds `verifiable_pseudonymize` / `verifiable_rekey` /
//! `verifiable_transcrypt` to the existing `WASM*Batch` types from
//! `data/wasm/batch.rs`. wasm-bindgen accepts multiple
//! `#[wasm_bindgen(js_class = "...")] impl X { ... }` blocks for the same
//! type as long as the `js_class` matches the original `js_name`.

#[cfg(feature = "long")]
use crate::data::verifiable::long::{
    LongAttributeRekeyBatchProof, LongPseudonymPseudonymizationBatchProof,
    LongPseudonymRekeyBatchProof,
};
#[cfg(feature = "long")]
use crate::data::verifiable::records::LongRecordTranscryptionBatchProof;
use crate::data::verifiable::records::RecordTranscryptionBatchProof;
use crate::data::verifiable::simple::{
    AttributeRekeyBatchProof, PseudonymPseudonymizationBatchProof, PseudonymRekeyBatchProof,
};
use crate::data::wasm::batch::{
    WASMEncryptedAttributeBatch, WASMEncryptedPseudonymBatch, WASMEncryptedRecordBatch,
};
#[cfg(feature = "long")]
use crate::data::wasm::batch::{
    WASMLongEncryptedAttributeBatch, WASMLongEncryptedPseudonymBatch, WASMLongEncryptedRecordBatch,
};
use crate::factors::wasm::commitments::{
    WASMVerifiablePseudonymizationCommitment, WASMVerifiableRekeyCommitment,
    WASMVerifiableTranscryptionCommitment,
};
use crate::factors::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
use crate::factors::wasm::types::WASMPseudonymRekeyFactor;
use crate::factors::{AttributeRekeyInfo, PseudonymizationInfo};
use crate::verifier::VerifyError;
use crate::wasm_errors::{malformed_proof_err, verify_err_to_js};
use wasm_bindgen::prelude::*;

fn verify_err() -> JsValue {
    verify_err_to_js(VerifyError::ProofRejected)
}

// ---------------------------------------------------------------------------
// PseudonymPseudonymizationBatchProof
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_name = PseudonymPseudonymizationBatchProof)]
#[derive(Clone)]
pub struct WASMPseudonymPseudonymizationBatchProof(pub(crate) PseudonymPseudonymizationBatchProof);

impl From<PseudonymPseudonymizationBatchProof> for WASMPseudonymPseudonymizationBatchProof {
    fn from(p: PseudonymPseudonymizationBatchProof) -> Self {
        Self(p)
    }
}

impl From<WASMPseudonymPseudonymizationBatchProof> for PseudonymPseudonymizationBatchProof {
    fn from(p: WASMPseudonymPseudonymizationBatchProof) -> Self {
        p.0
    }
}

#[wasm_bindgen(js_class = PseudonymPseudonymizationBatchProof)]
impl WASMPseudonymPseudonymizationBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMPseudonymPseudonymizationBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMPseudonymPseudonymizationBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedPseudonymBatch,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.0)
            .map(|inner| WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedPseudonymBatch,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.0)
            .map(|inner| WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedPseudonymBatch,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMEncryptedPseudonymBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// PseudonymRekeyBatchProof
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_name = PseudonymRekeyBatchProof)]
#[derive(Clone)]
pub struct WASMPseudonymRekeyBatchProof(pub(crate) PseudonymRekeyBatchProof);

impl From<PseudonymRekeyBatchProof> for WASMPseudonymRekeyBatchProof {
    fn from(p: PseudonymRekeyBatchProof) -> Self {
        Self(p)
    }
}

impl From<WASMPseudonymRekeyBatchProof> for PseudonymRekeyBatchProof {
    fn from(p: WASMPseudonymRekeyBatchProof) -> Self {
        p.0
    }
}

#[wasm_bindgen(js_class = PseudonymRekeyBatchProof)]
impl WASMPseudonymRekeyBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMPseudonymRekeyBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMPseudonymRekeyBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedPseudonymBatch,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMEncryptedPseudonymBatch, JsValue> {
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedPseudonymBatch,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMEncryptedPseudonymBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// AttributeRekeyBatchProof
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_name = AttributeRekeyBatchProof)]
#[derive(Clone)]
pub struct WASMAttributeRekeyBatchProof(pub(crate) AttributeRekeyBatchProof);

impl From<AttributeRekeyBatchProof> for WASMAttributeRekeyBatchProof {
    fn from(p: AttributeRekeyBatchProof) -> Self {
        Self(p)
    }
}

impl From<WASMAttributeRekeyBatchProof> for AttributeRekeyBatchProof {
    fn from(p: WASMAttributeRekeyBatchProof) -> Self {
        p.0
    }
}

#[wasm_bindgen(js_class = AttributeRekeyBatchProof)]
impl WASMAttributeRekeyBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMAttributeRekeyBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMAttributeRekeyBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedAttributeBatch,
        new_public_key: &crate::keys::wasm::types::WASMAttributeSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMEncryptedAttributeBatch, JsValue> {
        let new_pk = crate::keys::AttributeSessionPublicKey::from(new_public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| WASMEncryptedAttributeBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedAttributeBatch,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMEncryptedAttributeBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMEncryptedAttributeBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongPseudonymPseudonymizationBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[wasm_bindgen(js_name = LongPseudonymPseudonymizationBatchProof)]
#[derive(Clone)]
pub struct WASMLongPseudonymPseudonymizationBatchProof(
    pub(crate) LongPseudonymPseudonymizationBatchProof,
);

#[cfg(feature = "long")]
impl From<LongPseudonymPseudonymizationBatchProof> for WASMLongPseudonymPseudonymizationBatchProof {
    fn from(p: LongPseudonymPseudonymizationBatchProof) -> Self {
        Self(p)
    }
}

#[cfg(feature = "long")]
impl From<WASMLongPseudonymPseudonymizationBatchProof> for LongPseudonymPseudonymizationBatchProof {
    fn from(p: WASMLongPseudonymPseudonymizationBatchProof) -> Self {
        p.0
    }
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongPseudonymPseudonymizationBatchProof)]
impl WASMLongPseudonymPseudonymizationBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMLongPseudonymPseudonymizationBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMLongPseudonymPseudonymizationBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedPseudonymBatch,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMLongEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &pk, &new_pk, &commitments.0)
            .map(|inner| WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedPseudonymBatch,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMLongEncryptedPseudonymBatch, JsValue> {
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &pk, &commitments.0)
            .map(|inner| WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedPseudonymBatch,
        commitments: &WASMVerifiablePseudonymizationCommitment,
    ) -> Result<WASMLongEncryptedPseudonymBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongPseudonymRekeyBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[wasm_bindgen(js_name = LongPseudonymRekeyBatchProof)]
#[derive(Clone)]
pub struct WASMLongPseudonymRekeyBatchProof(pub(crate) LongPseudonymRekeyBatchProof);

#[cfg(feature = "long")]
impl From<LongPseudonymRekeyBatchProof> for WASMLongPseudonymRekeyBatchProof {
    fn from(p: LongPseudonymRekeyBatchProof) -> Self {
        Self(p)
    }
}

#[cfg(feature = "long")]
impl From<WASMLongPseudonymRekeyBatchProof> for LongPseudonymRekeyBatchProof {
    fn from(p: WASMLongPseudonymRekeyBatchProof) -> Self {
        p.0
    }
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongPseudonymRekeyBatchProof)]
impl WASMLongPseudonymRekeyBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMLongPseudonymRekeyBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMLongPseudonymRekeyBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedPseudonymBatch,
        new_public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMLongEncryptedPseudonymBatch, JsValue> {
        let new_pk = crate::keys::PseudonymSessionPublicKey::from(new_public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedPseudonymBatch,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMLongEncryptedPseudonymBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMLongEncryptedPseudonymBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongAttributeRekeyBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[wasm_bindgen(js_name = LongAttributeRekeyBatchProof)]
#[derive(Clone)]
pub struct WASMLongAttributeRekeyBatchProof(pub(crate) LongAttributeRekeyBatchProof);

#[cfg(feature = "long")]
impl From<LongAttributeRekeyBatchProof> for WASMLongAttributeRekeyBatchProof {
    fn from(p: LongAttributeRekeyBatchProof) -> Self {
        Self(p)
    }
}

#[cfg(feature = "long")]
impl From<WASMLongAttributeRekeyBatchProof> for LongAttributeRekeyBatchProof {
    fn from(p: WASMLongAttributeRekeyBatchProof) -> Self {
        p.0
    }
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongAttributeRekeyBatchProof)]
impl WASMLongAttributeRekeyBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMLongAttributeRekeyBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMLongAttributeRekeyBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedAttributeBatch,
        new_public_key: &crate::keys::wasm::types::WASMAttributeSessionPublicKey,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMLongEncryptedAttributeBatch, JsValue> {
        let new_pk = crate::keys::AttributeSessionPublicKey::from(new_public_key.0 .0);
        self.0
            .verified_reconstruct_batch(&original.inner, &new_pk, &commitments.0)
            .map(|inner| WASMLongEncryptedAttributeBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedAttributeBatch,
        commitments: &WASMVerifiableRekeyCommitment,
    ) -> Result<WASMLongEncryptedAttributeBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMLongEncryptedAttributeBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// RecordTranscryptionBatchProof
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_name = RecordTranscryptionBatchProof)]
#[derive(Clone)]
pub struct WASMRecordTranscryptionBatchProof(pub(crate) RecordTranscryptionBatchProof);

impl From<RecordTranscryptionBatchProof> for WASMRecordTranscryptionBatchProof {
    fn from(p: RecordTranscryptionBatchProof) -> Self {
        Self(p)
    }
}

impl From<WASMRecordTranscryptionBatchProof> for RecordTranscryptionBatchProof {
    fn from(p: WASMRecordTranscryptionBatchProof) -> Self {
        p.0
    }
}

#[wasm_bindgen(js_class = RecordTranscryptionBatchProof)]
impl WASMRecordTranscryptionBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMRecordTranscryptionBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMRecordTranscryptionBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedRecordBatch,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        new_session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        let new_sk: crate::keys::SessionKeys = (*new_session_keys).into();
        self.0
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.0)
            .map(|inner| WASMEncryptedRecordBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedRecordBatch,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        self.0
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.0)
            .map(|inner| WASMEncryptedRecordBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMEncryptedRecordBatch,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMEncryptedRecordBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMEncryptedRecordBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// LongRecordTranscryptionBatchProof
// ---------------------------------------------------------------------------

#[cfg(feature = "long")]
#[wasm_bindgen(js_name = LongRecordTranscryptionBatchProof)]
#[derive(Clone)]
pub struct WASMLongRecordTranscryptionBatchProof(pub(crate) LongRecordTranscryptionBatchProof);

#[cfg(feature = "long")]
impl From<LongRecordTranscryptionBatchProof> for WASMLongRecordTranscryptionBatchProof {
    fn from(p: LongRecordTranscryptionBatchProof) -> Self {
        Self(p)
    }
}

#[cfg(feature = "long")]
impl From<WASMLongRecordTranscryptionBatchProof> for LongRecordTranscryptionBatchProof {
    fn from(p: WASMLongRecordTranscryptionBatchProof) -> Self {
        p.0
    }
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongRecordTranscryptionBatchProof)]
impl WASMLongRecordTranscryptionBatchProof {
    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(malformed_proof_err)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMLongRecordTranscryptionBatchProof, JsValue> {
        serde_json::from_str(json)
            .map(WASMLongRecordTranscryptionBatchProof)
            .map_err(malformed_proof_err)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedRecordBatch,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        new_session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMLongEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        let new_sk: crate::keys::SessionKeys = (*new_session_keys).into();
        self.0
            .verified_reconstruct_batch(&original.inner, &sk, &new_sk, &commitments.0)
            .map(|inner| WASMLongEncryptedRecordBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedRecordBatch,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMLongEncryptedRecordBatch, JsValue> {
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        self.0
            .verified_reconstruct_batch(&original.inner, &sk, &commitments.0)
            .map(|inner| WASMLongEncryptedRecordBatch { inner })
            .ok_or_else(verify_err)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstructBatch)]
    pub fn verified_reconstruct_batch(
        &self,
        original: &WASMLongEncryptedRecordBatch,
        commitments: &WASMVerifiableTranscryptionCommitment,
    ) -> Result<WASMLongEncryptedRecordBatch, JsValue> {
        self.0
            .verified_reconstruct_batch(&original.inner, &commitments.0)
            .map(|inner| WASMLongEncryptedRecordBatch { inner })
            .ok_or_else(verify_err)
    }
}

// ---------------------------------------------------------------------------
// Producer methods on the existing WASM*Batch types
//
// wasm-bindgen permits multiple `impl` blocks for the same class when each
// uses the matching `js_class = "..."` attribute. These mirror the Rust
// `verifiable_pseudonymize` / `verifiable_rekey` / `verifiable_transcrypt`
// inherent methods 1:1.
// ---------------------------------------------------------------------------

#[wasm_bindgen(js_class = EncryptedPseudonymBatch)]
impl WASMEncryptedPseudonymBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
    ) -> WASMPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        self.inner
            .verifiable_pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
    ) -> WASMPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.inner
            .verifiable_pseudonymize(&PseudonymizationInfo::from(info.0), &pk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
    ) -> WASMPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        self.inner
            .verifiable_pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .into()
    }

    #[wasm_bindgen(js_name = verifiableRekey)]
    pub fn verifiable_rekey(
        &mut self,
        info: &WASMPseudonymRekeyFactor,
    ) -> WASMPseudonymRekeyBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_rekey(&info.0, &mut rng).into()
    }
}

#[wasm_bindgen(js_class = EncryptedAttributeBatch)]
impl WASMEncryptedAttributeBatch {
    #[wasm_bindgen(js_name = verifiableRekey)]
    pub fn verifiable_rekey(
        &mut self,
        info: &WASMAttributeRekeyInfo,
    ) -> WASMAttributeRekeyBatchProof {
        let mut rng = rand::rng();
        self.inner
            .verifiable_rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
            .into()
    }
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongEncryptedPseudonymBatch)]
impl WASMLongEncryptedPseudonymBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
    ) -> WASMLongPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        self.inner
            .verifiable_pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::wasm::types::WASMPseudonymSessionPublicKey,
    ) -> WASMLongPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.inner
            .verifiable_pseudonymize(&PseudonymizationInfo::from(info.0), &pk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
    ) -> WASMLongPseudonymPseudonymizationBatchProof {
        let mut rng = rand::rng();
        self.inner
            .verifiable_pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .into()
    }

    #[wasm_bindgen(js_name = verifiableRekey)]
    pub fn verifiable_rekey(
        &mut self,
        info: &WASMPseudonymRekeyFactor,
    ) -> WASMLongPseudonymRekeyBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_rekey(&info.0, &mut rng).into()
    }
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongEncryptedAttributeBatch)]
impl WASMLongEncryptedAttributeBatch {
    #[wasm_bindgen(js_name = verifiableRekey)]
    pub fn verifiable_rekey(
        &mut self,
        info: &WASMAttributeRekeyInfo,
    ) -> WASMLongAttributeRekeyBatchProof {
        let mut rng = rand::rng();
        self.inner
            .verifiable_rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
            .into()
    }
}

#[wasm_bindgen(js_class = EncryptedRecordBatch)]
impl WASMEncryptedRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn verifiable_transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
    ) -> WASMRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_transcrypt(&info.0, &mut rng).into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn verifiable_transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> WASMRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .verifiable_transcrypt(&info.0, &sk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn verifiable_transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
    ) -> WASMRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_transcrypt(&info.0, &mut rng).into()
    }
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongEncryptedRecordBatch)]
impl WASMLongEncryptedRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn verifiable_transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
    ) -> WASMLongRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_transcrypt(&info.0, &mut rng).into()
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn verifiable_transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::wasm::types::WASMSessionKeys,
    ) -> WASMLongRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        let sk: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .verifiable_transcrypt(&info.0, &sk, &mut rng)
            .into()
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiableTranscrypt)]
    pub fn verifiable_transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
    ) -> WASMLongRecordTranscryptionBatchProof {
        let mut rng = rand::rng();
        self.inner.verifiable_transcrypt(&info.0, &mut rng).into()
    }
}
