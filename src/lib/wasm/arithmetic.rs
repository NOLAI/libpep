use crate::internal::arithmetic::*;
use derive_more::{Deref, From, Into};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

/// Element on a group. Can not be converted to a scalar. Supports addition and subtraction. Multiplication by a scalar is supported.
/// We use ristretto points to discard unsafe points and safely use the group operations in higher level protocols without any other cryptographic assumptions.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = GroupElement)]
pub struct WASMGroupElement(pub(crate) GroupElement);

#[wasm_bindgen(js_class = "GroupElement")]
impl WASMGroupElement {
    /// Encodes the group element as a 32-byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decodes a group element from a 32-byte array.
    #[wasm_bindgen(js_name = decode)]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMGroupElement> {
        GroupElement::decode_from_slice(bytes.as_slice()).map(WASMGroupElement)
    }
    /// Generates a random group element.
    #[wasm_bindgen]
    pub fn random() -> WASMGroupElement {
        GroupElement::random(&mut OsRng).into()
    }
    /// Decodes a group element from a 64-byte hash.
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMGroupElement {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        GroupElement::decode_from_hash(&arr).into()
    }
    /// Decodes a group element from a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMGroupElement> {
        GroupElement::decode_from_hex(hex).map(WASMGroupElement)
    }
    /// Encodes the group element as a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
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

/// Non-zero scalar. Supports addition, subtraction, multiplication, and inversion. Can be converted to a scalar that can be zero.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ScalarNonZero)]
pub struct WASMScalarNonZero(pub(crate) ScalarNonZero);

#[wasm_bindgen(js_class = "ScalarNonZero")]
impl WASMScalarNonZero {
    /// Encodes the scalar as a 32-byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decodes a scalar from a 32-byte array.
    #[wasm_bindgen(js_name = decode)]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMScalarNonZero> {
        ScalarNonZero::decode_from_slice(bytes.as_slice()).map(WASMScalarNonZero)
    }
    /// Decodes a scalar from a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarNonZero> {
        ScalarNonZero::decode_from_hex(hex).map(WASMScalarNonZero)
    }
    /// Encodes the scalar as a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    /// Generates a random non-zero scalar.
    #[wasm_bindgen]
    pub fn random() -> WASMScalarNonZero {
        ScalarNonZero::random(&mut OsRng).into()
    }
    /// Decodes a scalar from a 64-byte hash.
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMScalarNonZero {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        ScalarNonZero::decode_from_hash(&arr).into()
    }
    /// Returns scalar one.
    #[wasm_bindgen]
    pub fn one() -> WASMScalarNonZero {
        ScalarNonZero::one().into()
    }
    /// Inverts the scalar.
    #[wasm_bindgen]
    pub fn invert(&self) -> WASMScalarNonZero {
        self.0.invert().into()
    }
    /// Multiplies two scalars.
    #[wasm_bindgen]
    pub fn mul(&self, other: &WASMScalarNonZero) -> WASMScalarNonZero {
        (self.0 * other.0).into() // Guaranteed to be non-zero
    }
    /// Converts the scalar to a scalar that can be zero.
    #[wasm_bindgen(js_name = toCanBeZero)]
    pub fn to_can_be_zero(self) -> WASMScalarCanBeZero {
        let s: ScalarCanBeZero = self.0.into();
        WASMScalarCanBeZero(s)
    }
}

/// Scalar that can be zero. Supports addition and subtraction, but not multiplication or inversion.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ScalarCanBeZero)]
pub struct WASMScalarCanBeZero(pub(crate) ScalarCanBeZero);
#[wasm_bindgen(js_class = "ScalarCanBeZero")]
impl WASMScalarCanBeZero {
    /// Encodes the scalar as a 32-byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decodes a scalar from a 32-byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::decode_from_slice(bytes.as_slice()).map(WASMScalarCanBeZero)
    }
    /// Decodes a scalar from a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::decode_from_hex(hex).map(WASMScalarCanBeZero)
    }
    /// Encodes the scalar as a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    /// Returns scalar one.
    #[wasm_bindgen]
    pub fn one() -> WASMScalarCanBeZero {
        ScalarCanBeZero::one().into()
    }
    /// Returns scalar zero.
    #[wasm_bindgen]
    pub fn zero() -> WASMScalarCanBeZero {
        ScalarCanBeZero::zero().into()
    }
    /// Checks if the scalar is zero.
    #[wasm_bindgen(js_name = isZero)]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    /// Adds two scalars.
    #[wasm_bindgen]
    pub fn add(&self, other: &WASMScalarCanBeZero) -> WASMScalarCanBeZero {
        (self.0 + other.0).into()
    }
    /// Subtracts two scalars.
    #[wasm_bindgen]
    pub fn sub(&self, other: &WASMScalarCanBeZero) -> WASMScalarCanBeZero {
        (self.0 - other.0).into()
    }
    /// Tries to convert the scalar to a scalar that can not be zero.
    #[wasm_bindgen(js_name = toNonZero)]
    pub fn to_non_zero(self) -> Option<WASMScalarNonZero> {
        let s: ScalarNonZero = self.0.try_into().ok()?;
        Some(WASMScalarNonZero(s))
    }
}
