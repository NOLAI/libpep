//! WASM bindings for the encodings of identifiers and payloads as group elements.
//!
//! Every encoding must be such that no party can produce two encoded inputs with a known
//! discrete-log relation; encoding an identifier `x` as `x * G` is forbidden.

use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::protocol::context_or_default;
use libpep::encodings;
use wasm_bindgen::prelude::*;

/// The hash_to_group encoding of an identifier: hash_to_ristretto255 (RFC 9380) domain-separated
/// with the protocol context (`"HashToGroup-" || contextString`; the default context if
/// omitted). Not invertible.
#[wasm_bindgen(js_name = hashToGroup)]
pub fn wasm_hash_to_group(x: &[u8], context: Option<js_sys::Object>) -> WASMGroupElement {
    encodings::hash_to_group(x, &context_or_default(context.as_ref())).into()
}

/// The lizard encoding of a 16-byte string as a group element. Invertible with `decodeLizard`.
#[wasm_bindgen(js_name = encodeLizard)]
pub fn wasm_encode_lizard(data: &[u8]) -> Result<WASMGroupElement, JsValue> {
    let data: &[u8; 16] = data
        .try_into()
        .map_err(|_| JsValue::from_str("lizard encodes exactly 16 bytes"))?;
    Ok(encodings::encode_lizard(data).into())
}

/// Invert `encodeLizard`; `undefined` if the element is not a lizard encoding (such as a
/// reshuffled one).
#[wasm_bindgen(js_name = decodeLizard)]
pub fn wasm_decode_lizard(element: &WASMGroupElement) -> Option<Vec<u8>> {
    encodings::decode_lizard(&element.0).map(|x| x.to_vec())
}
