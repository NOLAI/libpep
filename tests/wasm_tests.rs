use wasm_bindgen_test::*;
use libpep::{encrypt, decrypt};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let message = "Hello, world!";
    let public_key = [/* 32 bytes of public key data */];
    let secret_key = [/* 32 bytes of secret key data */];

    let encrypted = encrypt(message, &public_key);
    let decrypted = decrypt(&encrypted, &secret_key);

    assert_eq!(message, decrypted);
}
