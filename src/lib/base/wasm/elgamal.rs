use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::base::elgamal::{decrypt, encrypt, ElGamal};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// An ElGamal ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ElGamal)]
pub struct WASMElGamal(pub(crate) ElGamal);
#[wasm_bindgen(js_class = "ElGamal")]
impl WASMElGamal {
    /// Encodes the ElGamal ciphertext as a byte array.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Decodes an ElGamal ciphertext from a byte array.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(v: Vec<u8>) -> Option<WASMElGamal> {
        ElGamal::from_slice(v.as_slice()).map(WASMElGamal)
    }

    /// Encodes the ElGamal ciphertext as a base64 string.
    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(self) -> String {
        self.0.to_base64()
    }

    /// Decodes an ElGamal ciphertext from a base64 string.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<WASMElGamal> {
        ElGamal::from_base64(s).map(WASMElGamal)
    }
}
/// Encrypts a message (group element) using the ElGamal encryption scheme.
#[wasm_bindgen(js_name = encrypt)]
pub fn encrypt_wasm(gm: &WASMGroupElement, gy: &WASMGroupElement) -> WASMElGamal {
    let mut rng = rand::rng();
    encrypt(gm, gy, &mut rng).into()
}
/// Decrypts an ElGamal ciphertext using the provided secret key and returns the group element.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
#[wasm_bindgen(js_name = decrypt)]
#[cfg(feature = "elgamal3")]
pub fn decrypt_wasm(encrypted: &WASMElGamal, y: &WASMScalarNonZero) -> Option<WASMGroupElement> {
    decrypt(encrypted, y).map(|x| x.into())
}

/// Decrypts an ElGamal ciphertext using the provided secret key and returns the group element.
#[wasm_bindgen(js_name = decrypt)]
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt_wasm(encrypted: &WASMElGamal, y: &WASMScalarNonZero) -> WASMGroupElement {
    decrypt(encrypted, y).into()
}
