use libpep::lib_wasm::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let secret_key = generate_secret_key();
    let public_key = get_public_key(&secret_key);
    let message = get_random();

    let encrypted = pep_encrypt(&message, &public_key);
    let decrypted = pep_decrypt(&encrypted, &secret_key);

    assert_eq!(message.to_vec(), decrypted);
}

#[wasm_bindgen_test]
fn test_encode_decode() {
    let pseudonym = get_random_hex();
    let encoded = encode_hex(&pseudonym);
    let decoded = decode_hex(&encoded);
    assert_eq!(pseudonym, decoded);
}
