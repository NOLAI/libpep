use wasm_bindgen::prelude::*;
use rand_core::OsRng;
use crate::arithmetic::*;
use crate::elgamal::*;
use crate::zkps::*;
use crate::proved::*;
use crate::utils::*;
use crate::distributed::*;
use crate::authenticity::*;

#[wasm_bindgen]
pub fn generate_keys() -> JsValue {
    let mut rng = OsRng;
    let (public_key, secret_key) = generate_global_keys(&mut rng);
    JsValue::from_serde(&(public_key.encode(), secret_key.encode())).unwrap()
}

#[wasm_bindgen]
pub fn encrypt_message(message: &str, public_key: &[u8]) -> JsValue {
    let mut rng = OsRng;
    let public_key = GroupElement::decode_from_slice(public_key).unwrap();
    let message = GroupElement::from_string(message).unwrap();
    let encrypted = encrypt(&message, &public_key, &mut rng);
    JsValue::from_serde(&encrypted.encode()).unwrap()
}

#[wasm_bindgen]
pub fn decrypt_message(encrypted: &[u8], secret_key: &[u8]) -> String {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let secret_key = ScalarNonZero::decode_from_slice(secret_key).unwrap();
    let decrypted = decrypt(&encrypted, &secret_key);
    decrypted.to_string()
}
