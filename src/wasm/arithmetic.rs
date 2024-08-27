use std::ops::Deref;
use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;
use crate::arithmetic::*;

#[wasm_bindgen(js_name = GroupElement)]
pub struct WASMGroupElement (GroupElement);
impl Deref for WASMGroupElement {
    type Target = GroupElement;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<GroupElement> for WASMGroupElement {
    fn from(x: GroupElement) -> Self {
        WASMGroupElement(x)
    }
}

#[wasm_bindgen(js_class = "GroupElement")]
impl WASMGroupElement {
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen(js_name = decode)]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMGroupElement> {
        GroupElement::decode_from_slice(&bytes.as_slice()).map(|x| WASMGroupElement(x))
    }
    #[wasm_bindgen]
    pub fn random() -> WASMGroupElement {
        GroupElement::random(&mut OsRng).into()
    }
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash
    (v: Vec<u8>) -> WASMGroupElement {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        GroupElement::decode_from_hash(&arr).into()
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMGroupElement> {
        GroupElement::decode_from_hex(hex).map(|x| WASMGroupElement(x))
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
    }

    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base_64(&self) -> String {
        self.0.encode_to_base64()
    }
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base_64(s: &str) -> Option<WASMGroupElement> {
        GroupElement::decode_from_base64(s).map(|x| WASMGroupElement(x))
    }

    #[wasm_bindgen]
    pub fn identity() -> WASMGroupElement {
        GroupElement::identity().into()
    }
    #[wasm_bindgen(js_name = G)]
    pub fn g() -> WASMGroupElement { G.into() }
    #[wasm_bindgen(js_name = generator)]
    pub fn generator() -> WASMGroupElement { G.into() }

    #[wasm_bindgen]
    pub fn add(&self, other: &WASMGroupElement) -> WASMGroupElement {
        WASMGroupElement(&self.0 + &other.0)
    }
    #[wasm_bindgen]
    pub fn sub(&self, other: &WASMGroupElement) -> WASMGroupElement {
        WASMGroupElement(&self.0 - &other.0)
    }
    #[wasm_bindgen]
    pub fn mul(&self, other: &WASMScalarNonZero) -> WASMGroupElement {
        (&other.0 * self.0).into() // Only possible if the scalar is non-zero
    }

}


#[wasm_bindgen(js_name = ScalarNonZero)]
pub struct WASMScalarNonZero (ScalarNonZero);
impl Deref for WASMScalarNonZero {
    type Target = ScalarNonZero;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl From<ScalarNonZero> for WASMScalarNonZero {
    fn from(x: ScalarNonZero) -> Self {
        WASMScalarNonZero(x)
    }
}
impl From<WASMScalarNonZero> for ScalarNonZero {
    fn from(x: WASMScalarNonZero) -> Self { x.0 }
}

#[wasm_bindgen(js_class = "ScalarNonZero")]
impl WASMScalarNonZero {
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen(js_name = decode)]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMScalarNonZero> {
        ScalarNonZero::decode_from_slice(&bytes.as_slice()).map(|x| WASMScalarNonZero(x))
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarNonZero> {
        ScalarNonZero::decode_from_hex(hex).map(|x| WASMScalarNonZero(x))
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
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
        (self.0 * &other.0).into() // Guaranteed to be non-zero
    }
    #[wasm_bindgen(js_name = toCanBeZero)]
    pub fn to_can_be_zero(self) -> WASMScalarCanBeZero {
        let s: ScalarCanBeZero = self.0.try_into().unwrap();
        WASMScalarCanBeZero(s)
    }
}

#[wasm_bindgen(js_name = ScalarCanBeZero)]
pub struct WASMScalarCanBeZero(ScalarCanBeZero);
impl Deref for WASMScalarCanBeZero {
    type Target = ScalarCanBeZero;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl From<ScalarCanBeZero> for WASMScalarCanBeZero {
    fn from(x: ScalarCanBeZero) -> Self {
        WASMScalarCanBeZero(x)
    }
}
impl From<WASMScalarCanBeZero> for ScalarCanBeZero {
    fn from(x: WASMScalarCanBeZero) -> Self { x.0 }
}

#[wasm_bindgen(js_class = "ScalarCanBeZero")]
impl WASMScalarCanBeZero {
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::decode_from_slice(&bytes.as_slice()).map(|x| WASMScalarCanBeZero(x))
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::decode_from_hex(hex).map(|x| WASMScalarCanBeZero(x))
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
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
        (self.0 + &other.0).into()
    }
    #[wasm_bindgen]
    pub fn sub(&self, other: &WASMScalarCanBeZero) -> WASMScalarCanBeZero {
        (self.0 - &other.0).into()
    }
    #[wasm_bindgen(js_name = toNonZero)]
    pub fn to_non_zero(&self) -> Option<WASMScalarNonZero> {
        let s: ScalarNonZero = self.0.try_into().ok()?;
        Some(WASMScalarNonZero(s))
    }
}
