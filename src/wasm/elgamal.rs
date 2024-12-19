use crate::low_level::elgamal::{decrypt, encrypt, ElGamal};
use crate::wasm::arithmetic::{WASMGroupElement, WASMScalarNonZero};
use derive_more::{Deref, From, Into};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ElGamal)]
pub struct WASMElGamal(ElGamal);
#[wasm_bindgen(js_class = "ElGamal")]
impl WASMElGamal {
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    #[wasm_bindgen]
    pub fn decode(v: Vec<u8>) -> Option<WASMElGamal> {
        ElGamal::decode_from_slice(v.as_slice()).map(WASMElGamal)
    }

    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(self) -> String {
        self.0.encode_to_base64()
    }

    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<WASMElGamal> {
        ElGamal::decode_from_base64(s).map(WASMElGamal)
    }
}
#[wasm_bindgen(js_name = encrypt)]
pub fn encrypt_wasm(gm: &WASMGroupElement, gy: &WASMGroupElement) -> WASMElGamal {
    let mut rng = OsRng;
    encrypt(gm, gy, &mut rng).into()
}
#[wasm_bindgen(js_name = decrypt)]
pub fn decrypt_wasm(encrypted: &WASMElGamal, y: &WASMScalarNonZero) -> WASMGroupElement {
    decrypt(encrypted, y).into()
}
