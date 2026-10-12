//! WASM bindings for hashing to the group and to scalars (RFC 9380, RFC 9497).

use crate::ciphersuite::ciphersuite_or_current;
use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::arithmetic::scalars::WASMScalarCanBeZero;
use libpep::elgamal::arithmetic::hashing;
use sha2::Sha512;
use wasm_bindgen::prelude::*;

/// `expand_message_xmd` of RFC 9380 with SHA-512: hash `msg` to `len_in_bytes` (at most 65535)
/// uniformly pseudorandom bytes under the domain separation tag `dst`, which is mixed in so that
/// the same message under two tags gives two unrelated outputs. `xmd` names the RFC's variant
/// for block-based hashes such as SHA-512.
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

/// The hash_to_group encoding of an identifier: hash_to_ristretto255 (RFC 9380) domain-separated
/// with the ciphersuite (`"HashToGroup-" || contextString`; the ciphersuite this build
/// implements if omitted). Not invertible; use `GroupElement.fromLizard` for an invertible
/// encoding.
#[wasm_bindgen(js_name = hashToGroup)]
pub fn wasm_hash_to_group(x: &[u8], ciphersuite: Option<js_sys::Object>) -> WASMGroupElement {
    hashing::hash_to_group_in(x, &ciphersuite_or_current(ciphersuite.as_ref())).into()
}

/// `hash_to_ristretto255` (RFC 9380) with SHA-512 under the complete domain separation tag
/// `dst`. Use `hashToGroup` to hash under the ciphersuite.
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
