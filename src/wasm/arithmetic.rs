use crate::internal::arithmetic::*;
use derive_more::{Deref, From, Into};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = GroupElement)]
pub struct WASMGroupElement(pub(crate) GroupElement);

#[wasm_bindgen(js_class = "GroupElement")]
impl WASMGroupElement {
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen(js_name = decode)]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMGroupElement> {
        GroupElement::decode_from_slice(bytes.as_slice()).map(WASMGroupElement)
    }
    #[wasm_bindgen]
    pub fn random() -> WASMGroupElement {
        GroupElement::random(&mut OsRng).into()
    }
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMGroupElement {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        GroupElement::decode_from_hash(&arr).into()
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMGroupElement> {
        GroupElement::decode_from_hex(hex).map(WASMGroupElement)
    }
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }

    #[wasm_bindgen]
    pub fn identity() -> WASMGroupElement {
        GroupElement::identity().into()
    }
    #[wasm_bindgen(js_name = G)]
    pub fn g() -> WASMGroupElement {
        G.into()
    }
    #[wasm_bindgen(js_name = generator)]
    pub fn generator() -> WASMGroupElement {
        G.into()
    }

    #[wasm_bindgen]
    pub fn add(&self, other: &WASMGroupElement) -> WASMGroupElement {
        WASMGroupElement(self.0 + other.0)
    }
    #[wasm_bindgen]
    pub fn sub(&self, other: &WASMGroupElement) -> WASMGroupElement {
        WASMGroupElement(self.0 - other.0)
    }
    #[wasm_bindgen]
    pub fn mul(&self, other: &WASMScalarNonZero) -> WASMGroupElement {
        (other.0 * self.0).into() // Only possible if the scalar is non-zero
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ScalarNonZero)]
pub struct WASMScalarNonZero(pub(crate) ScalarNonZero);

#[wasm_bindgen(js_class = "ScalarNonZero")]
impl WASMScalarNonZero {
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen(js_name = decode)]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMScalarNonZero> {
        ScalarNonZero::decode_from_slice(bytes.as_slice()).map(WASMScalarNonZero)
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarNonZero> {
        ScalarNonZero::decode_from_hex(hex).map(WASMScalarNonZero)
    }
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    #[wasm_bindgen]
    pub fn random() -> WASMScalarNonZero {
        ScalarNonZero::random(&mut OsRng).into()
    }
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMScalarNonZero {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        ScalarNonZero::decode_from_hash(&arr).into()
    }
    #[wasm_bindgen]
    pub fn one() -> WASMScalarNonZero {
        ScalarNonZero::one().into()
    }
    #[wasm_bindgen]
    pub fn invert(&self) -> WASMScalarNonZero {
        self.0.invert().into()
    }
    #[wasm_bindgen]
    pub fn mul(&self, other: &WASMScalarNonZero) -> WASMScalarNonZero {
        (self.0 * other.0).into() // Guaranteed to be non-zero
    }
    #[wasm_bindgen(js_name = toCanBeZero)]
    pub fn to_can_be_zero(self) -> WASMScalarCanBeZero {
        let s: ScalarCanBeZero = self.0.into();
        WASMScalarCanBeZero(s)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ScalarCanBeZero)]
pub struct WASMScalarCanBeZero(pub(crate) ScalarCanBeZero);
#[wasm_bindgen(js_class = "ScalarCanBeZero")]
impl WASMScalarCanBeZero {
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::decode_from_slice(bytes.as_slice()).map(WASMScalarCanBeZero)
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::decode_from_hex(hex).map(WASMScalarCanBeZero)
    }
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    #[wasm_bindgen]
    pub fn one() -> WASMScalarCanBeZero {
        ScalarCanBeZero::one().into()
    }
    #[wasm_bindgen]
    pub fn zero() -> WASMScalarCanBeZero {
        ScalarCanBeZero::zero().into()
    }
    #[wasm_bindgen(js_name = isZero)]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    #[wasm_bindgen]
    pub fn add(&self, other: &WASMScalarCanBeZero) -> WASMScalarCanBeZero {
        (self.0 + other.0).into()
    }
    #[wasm_bindgen]
    pub fn sub(&self, other: &WASMScalarCanBeZero) -> WASMScalarCanBeZero {
        (self.0 - other.0).into()
    }
    #[wasm_bindgen(js_name = toNonZero)]
    pub fn to_non_zero(self) -> Option<WASMScalarNonZero> {
        let s: ScalarNonZero = self.0.try_into().ok()?;
        Some(WASMScalarNonZero(s))
    }
}
