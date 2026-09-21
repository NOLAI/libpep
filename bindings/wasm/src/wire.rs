//! WASM bindings for the wire formats of draft-doesburg-cfrg-coprf: batch requests and
//! responses as bytes in, bytes out.

use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::WASMElGamal;
use derive_more::{Deref, From, Into};
use libpep::wire::{BatchKind, BatchRequest, BatchResponse};
use wasm_bindgen::prelude::*;

/// The kind of data in a batch: pseudonyms (reshuffled and rekeyed) or attributes (rekeyed).
#[wasm_bindgen(js_name = BatchKind)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WASMBatchKind {
    Pseudonym = 1,
    Attribute = 2,
}

impl From<WASMBatchKind> for BatchKind {
    fn from(kind: WASMBatchKind) -> Self {
        match kind {
            WASMBatchKind::Pseudonym => BatchKind::Pseudonym,
            WASMBatchKind::Attribute => BatchKind::Attribute,
        }
    }
}

impl From<BatchKind> for WASMBatchKind {
    fn from(kind: BatchKind) -> Self {
        match kind {
            BatchKind::Pseudonym => WASMBatchKind::Pseudonym,
            BatchKind::Attribute => WASMBatchKind::Attribute,
        }
    }
}

/// An identifier argument: a `Uint8Array`, or a string for its UTF-8 encoding.
fn identifier(arg: &JsValue, what: &str) -> Result<Vec<u8>, JsValue> {
    if let Some(text) = arg.as_string() {
        return Ok(text.into_bytes());
    }
    if arg.is_instance_of::<js_sys::Uint8Array>() {
        return Ok(js_sys::Uint8Array::new(arg).to_vec());
    }
    Err(JsValue::from_str(&format!(
        "{what} must be a Uint8Array or a string"
    )))
}

fn js_error(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// The `BatchRequest` struct of draft-doesburg-cfrg-coprf: ciphertexts of one kind to transcrypt.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = BatchRequest)]
pub struct WASMBatchRequest(pub(crate) BatchRequest);

#[wasm_bindgen(js_class = "BatchRequest")]
impl WASMBatchRequest {
    /// Assemble a request. Identifiers are `Uint8Array`s or strings; `items` are the
    /// ciphertexts, encrypted under `yFrom`. Throws for an empty batch or an oversized field.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: WASMBatchKind,
        d_from: JsValue,
        d_to: JsValue,
        c_from: JsValue,
        c_to: JsValue,
        y_from: &WASMGroupElement,
        items: Vec<WASMElGamal>,
    ) -> Result<WASMBatchRequest, JsValue> {
        BatchRequest::new(
            kind.into(),
            identifier(&d_from, "dFrom")?,
            identifier(&d_to, "dTo")?,
            identifier(&c_from, "cFrom")?,
            identifier(&c_to, "cTo")?,
            y_from.0,
            items.into_iter().map(|e| e.0).collect(),
        )
        .map(Self)
        .map_err(js_error)
    }

    /// Encode as the draft's `BatchRequest` struct.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Decode the draft's `BatchRequest` struct. Throws for an unknown type, truncated input,
    /// trailing bytes, an empty batch or an invalid element.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<WASMBatchRequest, JsValue> {
        BatchRequest::from_bytes(&bytes).map(Self).map_err(js_error)
    }

    /// The kind of data in the batch.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> WASMBatchKind {
        self.0.kind().into()
    }

    /// The pseudonymization domain the data comes from.
    #[wasm_bindgen(getter, js_name = dFrom)]
    pub fn d_from(&self) -> Vec<u8> {
        self.0.d_from().to_vec()
    }

    /// The pseudonymization domain the data goes to.
    #[wasm_bindgen(getter, js_name = dTo)]
    pub fn d_to(&self) -> Vec<u8> {
        self.0.d_to().to_vec()
    }

    /// The encryption context the data comes from.
    #[wasm_bindgen(getter, js_name = cFrom)]
    pub fn c_from(&self) -> Vec<u8> {
        self.0.c_from().to_vec()
    }

    /// The encryption context the data goes to.
    #[wasm_bindgen(getter, js_name = cTo)]
    pub fn c_to(&self) -> Vec<u8> {
        self.0.c_to().to_vec()
    }

    /// The public key the items are encrypted under.
    #[wasm_bindgen(getter, js_name = yFrom)]
    pub fn y_from(&self) -> WASMGroupElement {
        WASMGroupElement(*self.0.y_from())
    }

    /// The ciphertexts.
    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMElGamal> {
        self.0.items().iter().copied().map(WASMElGamal).collect()
    }

    /// The number of items.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.0.items().len()
    }
}

/// The `BatchResponse` struct of draft-doesburg-cfrg-coprf: the transcrypted items and their key.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = BatchResponse)]
pub struct WASMBatchResponse(pub(crate) BatchResponse);

#[wasm_bindgen(js_class = "BatchResponse")]
impl WASMBatchResponse {
    /// Assemble a response. Throws for an empty batch.
    #[wasm_bindgen(constructor)]
    pub fn new(
        y_to: &WASMGroupElement,
        items: Vec<WASMElGamal>,
    ) -> Result<WASMBatchResponse, JsValue> {
        BatchResponse::new(y_to.0, items.into_iter().map(|e| e.0).collect())
            .map(Self)
            .map_err(js_error)
    }

    /// Encode as the draft's `BatchResponse` struct.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Decode the draft's `BatchResponse` struct. Throws for truncated input, trailing bytes,
    /// an empty batch or an invalid element.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<WASMBatchResponse, JsValue> {
        BatchResponse::from_bytes(&bytes)
            .map(Self)
            .map_err(js_error)
    }

    /// The public key the items are now encrypted under.
    #[wasm_bindgen(getter, js_name = yTo)]
    pub fn y_to(&self) -> WASMGroupElement {
        WASMGroupElement(*self.0.y_to())
    }

    /// The transcrypted ciphertexts.
    #[wasm_bindgen(getter)]
    pub fn items(&self) -> Vec<WASMElGamal> {
        self.0.items().iter().copied().map(WASMElGamal).collect()
    }

    /// The number of items.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.0.items().len()
    }
}
