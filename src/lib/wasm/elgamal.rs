use crate::low_level::elgamal::{decrypt, encrypt, ElGamal};
use crate::wasm::arithmetic::{WASMGroupElement, WASMScalarNonZero};
use derive_more::{Deref, From, Into};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

/// An ElGamal ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ElGamal)]
pub struct WASMElGamal(ElGamal);
#[wasm_bindgen(js_class = "ElGamal")]
impl WASMElGamal {
    /// Encodes the ElGamal ciphertext as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    /// Decodes an ElGamal ciphertext from a byte array.
    #[wasm_bindgen]
    pub fn decode(v: Vec<u8>) -> Option<WASMElGamal> {
        ElGamal::decode_from_slice(v.as_slice()).map(WASMElGamal)
    }

    /// Encodes the ElGamal ciphertext as a base64 string.
    #[wasm_bindgen(js_name = asBase64)]
    pub fn as_base64(self) -> String {
        self.0.encode_as_base64()
    }

    /// Decodes an ElGamal ciphertext from a base64 string.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<WASMElGamal> {
        ElGamal::decode_from_base64(s).map(WASMElGamal)
    }
}
/// Encrypts a message (group element) using the ElGamal encryption scheme.
#[wasm_bindgen(js_name = encrypt)]
pub fn encrypt_wasm(gm: &WASMGroupElement, gy: &WASMGroupElement) -> WASMElGamal {
    let mut rng = OsRng;
    encrypt(gm, gy, &mut rng).into()
}
/// Decrypts an ElGamal ciphertext using the provided secret key and returns the group element.
#[wasm_bindgen(js_name = decrypt)]
pub fn decrypt_wasm(encrypted: &WASMElGamal, y: &WASMScalarNonZero) -> WASMGroupElement {
    decrypt(encrypted, y).into()
}
