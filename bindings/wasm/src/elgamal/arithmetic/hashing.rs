//! WASM bindings for hashing to the group and to scalars (RFC 9380, RFC 9497).

use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::arithmetic::scalars::WASMScalarCanBeZero;
use libpep::elgamal::arithmetic::hashing;
use sha2::Sha512;
use wasm_bindgen::prelude::*;

/// `expand_message_xmd` of RFC 9380 with SHA-512: expand `msg` under the domain separation tag
/// `dst` to `len_in_bytes` (at most 65535) uniformly pseudorandom bytes.
#[wasm_bindgen(js_name = expandMessageXmdSha512)]
pub fn wasm_expand_message_xmd_sha512(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, JsValue> {
    if len_in_bytes > 65535 {
        return Err(JsValue::from_str("len_in_bytes must be at most 65535"));
    }
    Ok(hashing::expand_message_xmd::<Sha512>(
        msg,
        dst,
        len_in_bytes,
    ))
}

/// `hash_to_ristretto255` (RFC 9380) with SHA-512 under the complete domain separation tag
/// `dst`. Use `hashToGroup` to hash under a protocol context.
#[wasm_bindgen(js_name = hashToGroupWithDst)]
pub fn wasm_hash_to_group_with_dst(msg: &[u8], dst: &[u8]) -> WASMGroupElement {
    hashing::hash_to_group(msg, dst).into()
}

/// `HashToScalar` of the ristretto255-SHA512 ciphersuite of RFC 9497 under the complete domain
/// separation tag `dst`. The result can be zero.
#[wasm_bindgen(js_name = hashToScalarWithDst)]
pub fn wasm_hash_to_scalar_with_dst(msg: &[u8], dst: &[u8]) -> WASMScalarCanBeZero {
    hashing::hash_to_scalar(msg, dst).into()
}
