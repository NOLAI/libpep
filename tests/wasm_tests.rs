use wasm_bindgen_test::*;
use libpep::lib_wasm::{decrypt, encrypt, encode};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let message = "Hello, world!";
    let public_key = [0u8; 32]; // Replace with actual public key data
    let secret_key = [1u8; 32]; // Replace with actual secret key data

    let encrypted = encrypt(message.as_bytes(), &public_key);
    let decrypted = decrypt(&encrypted, &secret_key);
    let decrypted_message = String::from_utf8(decrypted).unwrap();

    assert_eq!(message, decrypted_message);
}
