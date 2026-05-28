//! WASM wrappers around [`EncryptedBatch<E>`] — one concrete struct per encrypted shape.
//!
//! `wasm_bindgen` cannot expose generic Rust types to JavaScript, so we materialize
//! a dedicated `#[wasm_bindgen]` wrapper for each concrete `E` that participates in
//! batch operations. Each wrapper holds an `EncryptedBatch<E>` and mirrors the Rust
//! API 1:1: `new`, `len`, `is_empty`, `items` (clone of the inner items), `publicKey`
//! (under `batch-pk` only), and the batch operations (`pseudonymize`, `rekey`,
//! `transcrypt`) as appropriate per shape.
//!
//! The flat `*Batch` free functions in `transcryptor/wasm/batch.rs` are retained;
//! these wrappers are an additive layer letting JS callers hold a batch across
//! operations instead of round-tripping through `Vec<E>` between every step.

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::data::batch::EncryptedBatch;
#[cfg(feature = "long")]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::data::records::EncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::LongEncryptedRecord;
use crate::data::simple::{EncryptedAttribute, EncryptedPseudonym};
#[cfg(feature = "long")]
use crate::data::wasm::long::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
use crate::data::wasm::records::WASMEncryptedRecord;
#[cfg(feature = "long")]
use crate::data::wasm::records::WASMLongEncryptedRecord;
use crate::data::wasm::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::factors::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
use crate::factors::wasm::types::WASMPseudonymRekeyFactor;
use crate::factors::{AttributeRekeyInfo, PseudonymizationInfo};
use crate::wasm_errors::batch_err_to_js;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::wasm::types::{
    WASMAttributeSessionPublicKey, WASMPseudonymSessionPublicKey, WASMSessionKeys,
};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// EncryptedPseudonymBatch
// ---------------------------------------------------------------------------

/// A batch of encrypted pseudonyms sharing a single recipient session.
#[wasm_bindgen(js_name = EncryptedPseudonymBatch)]
#[derive(Clone)]
pub struct WASMEncryptedPseudonymBatch {
    pub(crate) inner: EncryptedBatch<EncryptedPseudonym>,
}

#[wasm_bindgen(js_class = EncryptedPseudonymBatch)]
impl WASMEncryptedPseudonymBatch {
    /// Construct a batch from items and the recipient public key the items
    /// were encrypted against.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMEncryptedPseudonym>,
        public_key: &WASMPseudonymSessionPublicKey,
    ) -> Result<WASMEncryptedPseudonymBatch, JsValue> {
        let items: Vec<EncryptedPseudonym> = items.into_iter().map(|e| e.0).collect();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let inner =
            EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    /// Construct a batch from items.
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(constructor)]
    pub fn new(items: Vec<WASMEncryptedPseudonym>) -> Result<WASMEncryptedPseudonymBatch, JsValue> {
        let items: Vec<EncryptedPseudonym> = items.into_iter().map(|e| e.0).collect();
        let inner = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    /// Number of items in the batch.
    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the batch is empty.
    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clone of the inner items as a JS array.
    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMEncryptedPseudonym> {
        self.inner
            .as_items()
            .iter()
            .map(|e| WASMEncryptedPseudonym(*e))
            .collect()
    }

    /// Recipient public key the batch is currently encrypted against.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> WASMPseudonymSessionPublicKey {
        WASMPseudonymSessionPublicKey(WASMGroupElement::from(self.inner.public_key.0))
    }

    /// Pseudonymize every item in the batch and shuffle.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(&mut self, info: &WASMPseudonymizationInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Pseudonymize every item in the batch and shuffle.
    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
        public_key: &WASMPseudonymSessionPublicKey,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.inner
            .pseudonymize(&PseudonymizationInfo::from(info.0), &pk, &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Pseudonymize every item in the batch and shuffle.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(&mut self, info: &WASMPseudonymizationInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Rekey every item in the batch and shuffle.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMPseudonymRekeyFactor) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Rekey every item in the batch and shuffle.
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMPseudonymRekeyFactor) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Transcrypt every item in the batch and shuffle.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Transcrypt every item in the batch and shuffle.
    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        public_key: &WASMPseudonymSessionPublicKey,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.inner
            .transcrypt(&info.0, &pk, &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Transcrypt every item in the batch and shuffle.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }
}

// ---------------------------------------------------------------------------
// EncryptedAttributeBatch
// ---------------------------------------------------------------------------

/// A batch of encrypted attributes sharing a single recipient session.
#[wasm_bindgen(js_name = EncryptedAttributeBatch)]
#[derive(Clone)]
pub struct WASMEncryptedAttributeBatch {
    pub(crate) inner: EncryptedBatch<EncryptedAttribute>,
}

#[wasm_bindgen(js_class = EncryptedAttributeBatch)]
impl WASMEncryptedAttributeBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMEncryptedAttribute>,
        public_key: &WASMAttributeSessionPublicKey,
    ) -> Result<WASMEncryptedAttributeBatch, JsValue> {
        let items: Vec<EncryptedAttribute> = items.into_iter().map(|e| e.0).collect();
        let pk = crate::keys::AttributeSessionPublicKey::from(public_key.0 .0);
        let inner =
            EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(constructor)]
    pub fn new(items: Vec<WASMEncryptedAttribute>) -> Result<WASMEncryptedAttributeBatch, JsValue> {
        let items: Vec<EncryptedAttribute> = items.into_iter().map(|e| e.0).collect();
        let inner = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMEncryptedAttribute> {
        self.inner
            .as_items()
            .iter()
            .map(|e| WASMEncryptedAttribute(*e))
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> WASMAttributeSessionPublicKey {
        WASMAttributeSessionPublicKey(WASMGroupElement::from(self.inner.public_key.0))
    }

    /// Rekey every item in the batch and shuffle.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMAttributeRekeyInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMAttributeRekeyInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    /// Transcrypt every item in the batch and shuffle.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        public_key: &WASMAttributeSessionPublicKey,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let pk = crate::keys::AttributeSessionPublicKey::from(public_key.0 .0);
        self.inner
            .transcrypt(&info.0, &pk, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }
}

// ---------------------------------------------------------------------------
// LongEncryptedPseudonymBatch
// ---------------------------------------------------------------------------

/// A batch of long encrypted pseudonyms sharing a single recipient session.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = LongEncryptedPseudonymBatch)]
#[derive(Clone)]
pub struct WASMLongEncryptedPseudonymBatch {
    pub(crate) inner: EncryptedBatch<LongEncryptedPseudonym>,
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongEncryptedPseudonymBatch)]
impl WASMLongEncryptedPseudonymBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMLongEncryptedPseudonym>,
        public_key: &WASMPseudonymSessionPublicKey,
    ) -> Result<WASMLongEncryptedPseudonymBatch, JsValue> {
        let items: Vec<LongEncryptedPseudonym> = items.into_iter().map(|e| e.0).collect();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        let inner =
            EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMLongEncryptedPseudonym>,
    ) -> Result<WASMLongEncryptedPseudonymBatch, JsValue> {
        let items: Vec<LongEncryptedPseudonym> = items.into_iter().map(|e| e.0).collect();
        let inner = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMLongEncryptedPseudonym> {
        self.inner
            .as_items()
            .iter()
            .map(|e| WASMLongEncryptedPseudonym(e.clone()))
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> WASMPseudonymSessionPublicKey {
        WASMPseudonymSessionPublicKey(WASMGroupElement::from(self.inner.public_key.0))
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(&mut self, info: &WASMPseudonymizationInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(
        &mut self,
        info: &WASMPseudonymizationInfo,
        public_key: &WASMPseudonymSessionPublicKey,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.inner
            .pseudonymize(&PseudonymizationInfo::from(info.0), &pk, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(&mut self, info: &WASMPseudonymizationInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .pseudonymize(&PseudonymizationInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMPseudonymRekeyFactor) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMPseudonymRekeyFactor) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        public_key: &WASMPseudonymSessionPublicKey,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);
        self.inner
            .transcrypt(&info.0, &pk, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }
}

// ---------------------------------------------------------------------------
// LongEncryptedAttributeBatch
// ---------------------------------------------------------------------------

/// A batch of long encrypted attributes sharing a single recipient session.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = LongEncryptedAttributeBatch)]
#[derive(Clone)]
pub struct WASMLongEncryptedAttributeBatch {
    pub(crate) inner: EncryptedBatch<LongEncryptedAttribute>,
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongEncryptedAttributeBatch)]
impl WASMLongEncryptedAttributeBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMLongEncryptedAttribute>,
        public_key: &WASMAttributeSessionPublicKey,
    ) -> Result<WASMLongEncryptedAttributeBatch, JsValue> {
        let items: Vec<LongEncryptedAttribute> = items.into_iter().map(|e| e.0).collect();
        let pk = crate::keys::AttributeSessionPublicKey::from(public_key.0 .0);
        let inner =
            EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMLongEncryptedAttribute>,
    ) -> Result<WASMLongEncryptedAttributeBatch, JsValue> {
        let items: Vec<LongEncryptedAttribute> = items.into_iter().map(|e| e.0).collect();
        let inner = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMLongEncryptedAttribute> {
        self.inner
            .as_items()
            .iter()
            .map(|e| WASMLongEncryptedAttribute(e.clone()))
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> WASMAttributeSessionPublicKey {
        WASMAttributeSessionPublicKey(WASMGroupElement::from(self.inner.public_key.0))
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMAttributeRekeyInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&mut self, info: &WASMAttributeRekeyInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .rekey(&AttributeRekeyInfo::from(info.0), &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        public_key: &WASMAttributeSessionPublicKey,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let pk = crate::keys::AttributeSessionPublicKey::from(public_key.0 .0);
        self.inner
            .transcrypt(&info.0, &pk, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }
}

// ---------------------------------------------------------------------------
// EncryptedRecordBatch
// ---------------------------------------------------------------------------

/// A batch of encrypted records sharing a single recipient session.
#[wasm_bindgen(js_name = EncryptedRecordBatch)]
#[derive(Clone)]
pub struct WASMEncryptedRecordBatch {
    pub(crate) inner: EncryptedBatch<EncryptedRecord>,
}

#[wasm_bindgen(js_class = EncryptedRecordBatch)]
impl WASMEncryptedRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMEncryptedRecord>,
        session_keys: &WASMSessionKeys,
    ) -> Result<WASMEncryptedRecordBatch, JsValue> {
        let items: Vec<EncryptedRecord> = items.into_iter().map(EncryptedRecord::from).collect();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        let inner =
            EncryptedBatch::new(items, keys).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(constructor)]
    pub fn new(items: Vec<WASMEncryptedRecord>) -> Result<WASMEncryptedRecordBatch, JsValue> {
        let items: Vec<EncryptedRecord> = items.into_iter().map(EncryptedRecord::from).collect();
        let inner = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMEncryptedRecord> {
        self.inner
            .as_items()
            .iter()
            .cloned()
            .map(WASMEncryptedRecord::from)
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> WASMSessionKeys {
        WASMSessionKeys::from(self.inner.public_key)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        session_keys: &WASMSessionKeys,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .transcrypt(&info.0, &keys, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }
}

// ---------------------------------------------------------------------------
// LongEncryptedRecordBatch
// ---------------------------------------------------------------------------

/// A batch of long encrypted records sharing a single recipient session.
#[cfg(feature = "long")]
#[wasm_bindgen(js_name = LongEncryptedRecordBatch)]
#[derive(Clone)]
pub struct WASMLongEncryptedRecordBatch {
    pub(crate) inner: EncryptedBatch<LongEncryptedRecord>,
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongEncryptedRecordBatch)]
impl WASMLongEncryptedRecordBatch {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMLongEncryptedRecord>,
        session_keys: &WASMSessionKeys,
    ) -> Result<WASMLongEncryptedRecordBatch, JsValue> {
        let items: Vec<LongEncryptedRecord> =
            items.into_iter().map(LongEncryptedRecord::from).collect();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        let inner =
            EncryptedBatch::new(items, keys).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        items: Vec<WASMLongEncryptedRecord>,
    ) -> Result<WASMLongEncryptedRecordBatch, JsValue> {
        let items: Vec<LongEncryptedRecord> =
            items.into_iter().map(LongEncryptedRecord::from).collect();
        let inner = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(getter)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMLongEncryptedRecord> {
        self.inner
            .as_items()
            .iter()
            .cloned()
            .map(WASMLongEncryptedRecord::from)
            .collect()
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> WASMSessionKeys {
        WASMSessionKeys::from(self.inner.public_key)
    }

    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(
        &mut self,
        info: &WASMTranscryptionInfo,
        session_keys: &WASMSessionKeys,
    ) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        let keys: crate::keys::SessionKeys = (*session_keys).into();
        self.inner
            .transcrypt(&info.0, &keys, &mut rng)
            .map_err(batch_err_to_js)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcrypt)]
    pub fn transcrypt(&mut self, info: &WASMTranscryptionInfo) -> Result<(), JsValue> {
        let mut rng = rand::rng();
        self.inner
            .transcrypt(&info.0, &mut rng)
            .map_err(batch_err_to_js)
    }
}
