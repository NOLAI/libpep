use super::super::data::*;
use super::super::padding::Padded;
use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::base::wasm::elgamal::WASMElGamal;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A pseudonym that can be used to identify a user.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = Pseudonym)]
pub struct WASMPseudonym(pub(crate) Pseudonym);

#[wasm_bindgen(js_class = "Pseudonym")]
impl WASMPseudonym {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        Self(Pseudonym::from_point(x.0))
    }

    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(&self) -> WASMGroupElement {
        self.0.value.into()
    }

    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::rng();
        Self(Pseudonym::random(&mut rng))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMPseudonym> {
        Pseudonym::from_slice(&bytes).map(Self)
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMPseudonym> {
        Pseudonym::from_hex(hex).map(Self)
    }

    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMPseudonym {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Pseudonym::from_hash(&arr).into()
    }

    #[wasm_bindgen(js_name = fromLizard)]
    pub fn from_lizard(data: Vec<u8>) -> Option<WASMPseudonym> {
        if data.len() != 16 {
            return None;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data);
        Some(Self(Pseudonym::from_lizard(&arr)))
    }

    #[wasm_bindgen(js_name = toLizard)]
    pub fn to_lizard(&self) -> Option<Vec<u8>> {
        self.0.to_lizard().map(|x| x.to_vec())
    }

    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: Vec<u8>) -> Option<WASMPseudonym> {
        Pseudonym::from_bytes_padded(&data).ok().map(Self)
    }

    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Option<WASMPseudonym> {
        Pseudonym::from_string_padded(text).ok().map(Self)
    }

    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Option<String> {
        self.0.to_string_padded().ok()
    }

    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Option<Vec<u8>> {
        self.0.to_bytes_padded().ok()
    }
}

/// An attribute which should not be identifiable.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = Attribute)]
pub struct WASMAttribute(pub(crate) Attribute);

#[wasm_bindgen(js_class = "Attribute")]
impl WASMAttribute {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        Self(Attribute::from_point(x.0))
    }

    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(&self) -> WASMGroupElement {
        self.0.value.into()
    }

    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::rng();
        Self(Attribute::random(&mut rng))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMAttribute> {
        Attribute::from_slice(&bytes).map(Self)
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMAttribute> {
        Attribute::from_hex(hex).map(Self)
    }

    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMAttribute {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Attribute::from_hash(&arr).into()
    }

    #[wasm_bindgen(js_name = fromLizard)]
    pub fn from_lizard(data: Vec<u8>) -> Option<WASMAttribute> {
        if data.len() != 16 {
            return None;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data);
        Some(Self(Attribute::from_lizard(&arr)))
    }

    #[wasm_bindgen(js_name = toLizard)]
    pub fn to_lizard(&self) -> Option<Vec<u8>> {
        self.0.to_lizard().map(|x| x.to_vec())
    }

    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: Vec<u8>) -> Option<WASMAttribute> {
        Attribute::from_bytes_padded(&data).ok().map(Self)
    }

    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Option<WASMAttribute> {
        Attribute::from_string_padded(text).ok().map(Self)
    }

    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Option<String> {
        self.0.to_string_padded().ok()
    }

    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Option<Vec<u8>> {
        self.0.to_bytes_padded().ok()
    }
}

/// An encrypted pseudonym.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = EncryptedPseudonym)]
pub struct WASMEncryptedPseudonym(pub(crate) EncryptedPseudonym);

#[wasm_bindgen(js_class = "EncryptedPseudonym")]
impl WASMEncryptedPseudonym {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        Self(EncryptedPseudonym::from(x.0))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(v: Vec<u8>) -> Option<WASMEncryptedPseudonym> {
        EncryptedPseudonym::from_slice(&v).map(Self)
    }

    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<WASMEncryptedPseudonym> {
        EncryptedPseudonym::from_base64(s).map(Self)
    }
}

/// An encrypted attribute.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = EncryptedAttribute)]
pub struct WASMEncryptedAttribute(pub(crate) EncryptedAttribute);

#[wasm_bindgen(js_class = "EncryptedAttribute")]
impl WASMEncryptedAttribute {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        Self(EncryptedAttribute::from(x.0))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(v: Vec<u8>) -> Option<WASMEncryptedAttribute> {
        EncryptedAttribute::from_slice(&v).map(Self)
    }

    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<WASMEncryptedAttribute> {
        EncryptedAttribute::from_base64(s).map(Self)
    }
}
