use crate::arithmetic::scalars::ScalarTraits;
use crate::arithmetic::scalars::{ScalarCanBeZero, ScalarNonZero};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// Non-zero scalar. Supports addition, subtraction, multiplication, and inversion. Can be converted to a scalar that can be zero.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ScalarNonZero)]
pub struct WASMScalarNonZero(pub(crate) ScalarNonZero);

#[wasm_bindgen(js_class = "ScalarNonZero")]
impl WASMScalarNonZero {
    /// Encodes the scalar as a 32-byte array.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
    /// Decodes a scalar from a 32-byte array.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMScalarNonZero> {
        ScalarNonZero::from_slice(bytes.as_slice()).map(WASMScalarNonZero)
    }
    /// Decodes a scalar from a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarNonZero> {
        ScalarNonZero::from_hex(hex).map(WASMScalarNonZero)
    }
    /// Encodes the scalar as a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
    /// Generates a random non-zero scalar.
    #[wasm_bindgen]
    pub fn random() -> WASMScalarNonZero {
        ScalarNonZero::random(&mut rand::rng()).into()
    }
    /// Decodes a scalar from a 64-byte hash.
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> WASMScalarNonZero {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        ScalarNonZero::from_hash(&arr).into()
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
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
    /// Decodes a scalar from a 32-byte array.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::from_slice(bytes.as_slice()).map(WASMScalarCanBeZero)
    }
    /// Decodes a scalar from a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMScalarCanBeZero> {
        ScalarCanBeZero::from_hex(hex).map(WASMScalarCanBeZero)
    }
    /// Encodes the scalar as a hexadecimal string of 64 characters.
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
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

    /// Generates a random scalar (that can be zero, but is extremely unlikely to be).
    #[wasm_bindgen]
    pub fn random() -> WASMScalarCanBeZero {
        ScalarCanBeZero::random(&mut rand::rng()).into()
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
