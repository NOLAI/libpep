use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// Element on a group. Can not be converted to a scalar. Supports addition and subtraction. Multiplication by a scalar is supported.
/// We use ristretto points to discard unsafe points and safely use the group operations in higher level protocols without any other cryptographic assumptions.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = GroupElement)]
pub struct WASMGroupElement(pub(crate) GroupElement);

#[wasm_bindgen(js_class = "GroupElement")]
impl WASMGroupElement {
    /// Encodes the group element as a 32-byte array.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
    /// Decodes a group element from a 32-byte array.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMGroupElement> {
        GroupElement::from_slice(bytes.as_slice()).map(WASMGroupElement)
    }
    /// Generates a random group element.
    #[wasm_bindgen]
    pub fn random() -> WASMGroupElement {
        GroupElement::random(&mut rand::rng()).into()
    }
    /// Decodes a group element from a 64-byte hash.
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMGroupElement {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        GroupElement::from_hash(&arr).into()
    }
    /// Decodes a group element from a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMGroupElement> {
        GroupElement::from_hex(hex).map(WASMGroupElement)
    }
    /// Encodes the group element as a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns the identity element of the group.
    #[wasm_bindgen]
    pub fn identity() -> WASMGroupElement {
        GroupElement::identity().into()
    }
    /// Returns the generator of the group.
    #[wasm_bindgen(js_name = G)]
    pub fn g() -> WASMGroupElement {
        G.into()
    }
    /// Returns the generator of the group.
    #[wasm_bindgen(js_name = generator)]
    pub fn generator() -> WASMGroupElement {
        G.into()
    }

    /// Adds two group elements.
    #[wasm_bindgen]
    pub fn add(&self, other: &WASMGroupElement) -> WASMGroupElement {
        WASMGroupElement(self.0 + other.0)
    }
    /// Subtracts two group elements.
    #[wasm_bindgen]
    pub fn sub(&self, other: &WASMGroupElement) -> WASMGroupElement {
        WASMGroupElement(self.0 - other.0)
    }
    /// Multiplies a group element by a scalar.
    #[wasm_bindgen]
    pub fn mul(&self, other: &WASMScalarNonZero) -> WASMGroupElement {
        (other.0 * self.0).into() // Only possible if the scalar is non-zero
    }
}
