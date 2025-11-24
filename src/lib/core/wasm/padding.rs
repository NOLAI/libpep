//! WASM bindings for PKCS#7 padding operations on Pseudonym and Attribute types.
//!
//! Note: These are also exposed as methods on WASMPseudonym and WASMAttribute in core.rs.
//! This module provides standalone function versions for API completeness.

use super::data::{WASMAttribute, WASMPseudonym};
use crate::core::data::{Attribute, Pseudonym};
use crate::core::padding::Padded;
use wasm_bindgen::prelude::*;

/// Encodes a byte array (up to 15 bytes) into a `Pseudonym` using PKCS#7 padding.
#[wasm_bindgen(js_name = pseudonymFromBytesPadded)]
pub fn wasm_pseudonym_from_bytes_padded(data: Vec<u8>) -> Option<WASMPseudonym> {
    Pseudonym::from_bytes_padded(&data).ok().map(WASMPseudonym)
}

/// Encodes a string (up to 15 bytes) into a `Pseudonym` using PKCS#7 padding.
#[wasm_bindgen(js_name = pseudonymFromStringPadded)]
pub fn wasm_pseudonym_from_string_padded(text: &str) -> Option<WASMPseudonym> {
    Pseudonym::from_string_padded(text).ok().map(WASMPseudonym)
}

/// Decodes a `Pseudonym` back to the original string.
#[wasm_bindgen(js_name = pseudonymToStringPadded)]
pub fn wasm_pseudonym_to_string_padded(pseudonym: &WASMPseudonym) -> Option<String> {
    pseudonym.0.to_string_padded().ok()
}

/// Decodes a `Pseudonym` back to the original byte array.
#[wasm_bindgen(js_name = pseudonymToBytesPadded)]
pub fn wasm_pseudonym_to_bytes_padded(pseudonym: &WASMPseudonym) -> Option<Vec<u8>> {
    pseudonym.0.to_bytes_padded().ok()
}

/// Encodes a byte array (up to 15 bytes) into an `Attribute` using PKCS#7 padding.
#[wasm_bindgen(js_name = attributeFromBytesPadded)]
pub fn wasm_attribute_from_bytes_padded(data: Vec<u8>) -> Option<WASMAttribute> {
    Attribute::from_bytes_padded(&data).ok().map(WASMAttribute)
}

/// Encodes a string (up to 15 bytes) into an `Attribute` using PKCS#7 padding.
#[wasm_bindgen(js_name = attributeFromStringPadded)]
pub fn wasm_attribute_from_string_padded(text: &str) -> Option<WASMAttribute> {
    Attribute::from_string_padded(text).ok().map(WASMAttribute)
}

/// Decodes an `Attribute` back to the original string.
#[wasm_bindgen(js_name = attributeToStringPadded)]
pub fn wasm_attribute_to_string_padded(attribute: &WASMAttribute) -> Option<String> {
    attribute.0.to_string_padded().ok()
}

/// Decodes an `Attribute` back to the original byte array.
#[wasm_bindgen(js_name = attributeToBytesPadded)]
pub fn wasm_attribute_to_bytes_padded(attribute: &WASMAttribute) -> Option<Vec<u8>> {
    attribute.0.to_bytes_padded().ok()
}
