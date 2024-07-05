use wasm_bindgen::prelude::*;
use rand_core::OsRng;
use crate::arithmetic::*;
use crate::elgamal::*;
use crate::primitives::*;


#[wasm_bindgen]
pub fn get_random() -> Vec<u8> {
    let mut rng = OsRng;
    let random = GroupElement::random(&mut rng);
    random.encode().to_vec().into()
}
#[wasm_bindgen]
pub fn get_random_hex() -> String {
    let mut rng = OsRng;
    let random = GroupElement::random(&mut rng);
    random.to_hex()
}

#[wasm_bindgen]
pub fn encode_hex(m: &str) -> Vec<u8> {
    GroupElement::from_hex(m).unwrap().encode().to_vec().into()
}

#[wasm_bindgen]
pub fn decode_hex(m: &[u8]) -> String {
    GroupElement::decode_from_slice(m).unwrap().to_hex()
}

#[wasm_bindgen]
pub fn generate_secret_key() -> Vec<u8> {
    let mut rng = OsRng;
    let secret = ScalarNonZero::random(&mut rng);
    secret.encode().to_vec().into()
}
#[wasm_bindgen]
pub fn get_public_key(secret_key: &[u8]) -> Vec<u8> {
    let secret = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(secret_key).unwrap()).unwrap();
    let public = secret * G;
    public.encode().to_vec().into()
}

#[wasm_bindgen]
pub fn pep_encrypt(message: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    let public_key = GroupElement::decode_from_slice(public_key).unwrap();
    let message = GroupElement::decode_from_slice(message).unwrap();
    let encrypted = encrypt(&message, &public_key, &mut rng);
    encrypted.encode().to_vec().into()
}

#[wasm_bindgen]
pub fn pep_decrypt(encrypted: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let secret_key = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(secret_key).unwrap()).unwrap();
    let decrypted = decrypt(&encrypted, &secret_key);
    decrypted.encode().to_vec().into()
}

#[wasm_bindgen]
pub fn pep_rerandomize(encrypted: &[u8], r: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let r = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(r).unwrap()).unwrap();
    let rerandomized = rerandomize(&encrypted, &r);
    rerandomized.encode().to_vec().into()
}

#[wasm_bindgen]
pub fn pep_reshuffle(encrypted: &[u8], s: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let s = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(s).unwrap()).unwrap();
    let reshuffled = reshuffle(&encrypted, &s);
    reshuffled.encode().to_vec().into()
}
#[wasm_bindgen]
pub fn pep_rekey(encrypted: &[u8], k: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let k = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(k).unwrap()).unwrap();
    let rekeyed = rekey(&encrypted, &k);
    rekeyed.encode().to_vec().into()
}
#[wasm_bindgen]
pub fn pep_rekey_from_to(encrypted: &[u8], k_from: &[u8], k_to: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let k_from = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(k_from).unwrap()).unwrap();
    let k_to = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(k_to).unwrap()).unwrap();
    let rekeyed = rekey_from_to(&encrypted, &k_from, &k_to);
    rekeyed.encode().to_vec().into()
}

#[wasm_bindgen]
pub fn pep_reshuffle_from_to(encrypted: &[u8], n_from: &[u8], n_to: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let n_from = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(n_from).unwrap()).unwrap();
    let n_to = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(n_to).unwrap()).unwrap();
    let reshuffled = reshuffle_from_to(&encrypted, &n_from, &n_to);
    reshuffled.encode().to_vec().into()
}

#[wasm_bindgen]
pub fn pep_rsk(encrypted: &[u8], s: &[u8], k: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let s = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(s).unwrap()).unwrap();
    let k = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(k).unwrap()).unwrap();
    let rsked = rsk(&encrypted, &s, &k);
    rsked.encode().to_vec().into()
}

#[wasm_bindgen]
pub fn pep_rsk_from_to(encrypted: &[u8], s_from: &[u8], s_to: &[u8], k_from: &[u8], k_to: &[u8]) -> Vec<u8> {
    let encrypted = ElGamal::decode(encrypted).unwrap();
    let s_from = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(s_from).unwrap()).unwrap();
    let s_to = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(s_to).unwrap()).unwrap();
    let k_from = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(k_from).unwrap()).unwrap();
    let k_to = ScalarNonZero::try_from(ScalarCanBeZero::decode_from_slice(k_to).unwrap()).unwrap();
    let rsked = rsk_from_to(&encrypted, &s_from, &s_to, &k_from, &k_to);
    rsked.encode().to_vec().into()
}

