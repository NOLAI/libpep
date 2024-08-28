use std::ops::Deref;
use rand_core::{OsRng};
use wasm_bindgen::prelude::*;
use crate::wasm::arithmetic::{WASMGroupElement, WASMScalarNonZero};
use crate::elgamal::{decrypt, ElGamal, encrypt};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = ElGamal)]
pub struct WASMElGamal (ElGamal);
impl Deref for WASMElGamal {
    type Target = ElGamal;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl From<ElGamal> for WASMElGamal {
    fn from(x: ElGamal) -> Self {
        WASMElGamal(x)
    }
}
impl From<WASMElGamal> for ElGamal {
    fn from(x: WASMElGamal) -> Self {
        x.0
    }
}
#[wasm_bindgen(js_class = "ElGamal")]
impl WASMElGamal {

    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    #[wasm_bindgen]
    pub fn decode(v: Vec<u8>) -> Option<WASMElGamal> {
        ElGamal::decode_from_slice(&v.as_slice()).map(|x| WASMElGamal(x))
    }

    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(&self) -> String {
        self.0.encode_to_base64()
    }

    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<WASMElGamal> {
        ElGamal::decode_from_base64(s).map(|x| WASMElGamal(x))
    }
}
#[wasm_bindgen(js_name = encrypt)]
pub fn encrypt_wasm(msg: &WASMGroupElement, public_key: &WASMGroupElement) -> WASMElGamal {
    let mut rng = OsRng;
    encrypt(&msg, &public_key, &mut rng).into()
}
#[wasm_bindgen(js_name = decrypt)]
pub fn decrypt_wasm(s: &WASMElGamal, secret_key: &WASMScalarNonZero) -> WASMGroupElement {
    decrypt(&s, &secret_key).into()
}
