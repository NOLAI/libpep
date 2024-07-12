use rand_core::OsRng;
use wasm_bindgen::prelude::*;
use crate::high_level::*;

#[wasm_bindgen]
pub struct SessionSecretKey(pub ScalarNonZero);
#[wasm_bindgen]
pub struct GlobalSecretKey(pub ScalarNonZero);
#[wasm_bindgen]
pub struct SessionPublicKey(pub GroupElement);
#[wasm_bindgen]
pub struct GlobalPublicKey(pub GroupElement);

#[wasm_bindgen]
pub struct Pseudonym(pub GroupElement);
#[wasm_bindgen]
pub struct DataPoint(pub GroupElement);
#[wasm_bindgen]
pub struct EncryptedPseudonym(pub ElGamal);
#[wasm_bindgen]
pub struct EncryptedDataPoint(pub ElGamal);

#[wasm_bindgen]

pub struct PseudonymizationContext(pub String);
#[wasm_bindgen]
pub struct EncryptionContext(pub String);

#[wasm_bindgen]
pub struct PseudonymizationSecret(pub String);
#[wasm_bindgen]
pub struct EncryptionSecret(pub String);

/// Generate a new global key pair
#[wasm_bindgen(js_name = generateGlobalKeys)]
pub fn generate_global_keys() -> (GlobalPublicKey, GlobalSecretKey) {
    let mut rng = rand::thread_rng();
    let sk = ScalarNonZero::random(&mut rng);
    let pk = sk * G;
    (GlobalPublicKey(pk), GlobalSecretKey(sk))
}

/// Generate a subkey from a global secret key, a context, and an encryption secret
#[wasm_bindgen(js_name = generateSessionKeys)]
pub fn generate_session_keys(global: &GlobalSecretKey, context: &EncryptionContext, encryption_secret: &EncryptionSecret) -> (SessionPublicKey, SessionSecretKey) {
    let k = make_decryption_factor(&encryption_secret.0, &context.0);
    let sk = k * &global.0;
    let pk = sk * G;
    (SessionPublicKey(pk), SessionSecretKey(sk))
}

/// Generate a new random pseudonym
#[wasm_bindgen(js_name = newRandomPseudonym)]
pub fn new_random_pseudonym() -> Pseudonym {
    let mut rng = OsRng;
    Pseudonym(GroupElement::random(&mut rng))
}

/// Encrypt a pseudonym
#[wasm_bindgen(js_name = encryptPseudonym)]
pub fn encrypt_pseudonym(p: &Pseudonym, pk: &SessionPublicKey) -> EncryptedPseudonym {
    let mut rng = OsRng;
    EncryptedPseudonym(encrypt(&p.0, &pk.0, &mut rng))
}

/// Decrypt an encrypted pseudonym
#[wasm_bindgen(js_name = decryptPseudonym)]
pub fn decrypt_pseudonym(p: &EncryptedPseudonym, sk: &SessionSecretKey) -> Pseudonym {
    Pseudonym(decrypt(&p.0, &sk.0))
}

/// Encrypt a data point
#[wasm_bindgen(js_name = encryptData)]
pub fn encrypt_data(data: &DataPoint, pk: &SessionPublicKey) -> EncryptedDataPoint {
    let mut rng = OsRng;
    EncryptedDataPoint(encrypt(&data.0, &pk.0, &mut rng))
}

/// Decrypt an encrypted data point
#[wasm_bindgen(js_name = decryptData)]
pub fn decrypt_data(data: &EncryptedDataPoint, sk: &SessionSecretKey) -> DataPoint {
    DataPoint(decrypt(&data.0, &sk.0))
}

/// Rerandomize the ciphertext of an encrypted pseudonym
#[wasm_bindgen(js_name = rerandomizeEncryptedPseudonym)]
pub fn rerandomize_encrypted_pseudonym(encrypted: EncryptedPseudonym) -> EncryptedPseudonym {
    let mut rng = OsRng;
    let r = ScalarNonZero::random(&mut rng);
    EncryptedPseudonym(rerandomize(&encrypted.0, &r))
}

/// Rerandomize the ciphertext of an encrypted data point
#[wasm_bindgen(js_name = rerandomizeEncryptedData)]
pub fn rerandomize_encrypted(encrypted: EncryptedDataPoint) -> EncryptedDataPoint {
    let mut rng = OsRng;
    let r = ScalarNonZero::random(&mut rng);
    EncryptedDataPoint(rerandomize(&encrypted.0, &r))
}

/// Pseudonymize an encrypted pseudonym, from one context to another context
#[wasm_bindgen(js_name = pseudonymize)]
pub fn pseudonymize(p: &EncryptedPseudonym, from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext, pseudonymization_secret: &PseudonymizationSecret, encryption_secret: &EncryptionSecret) -> EncryptedPseudonym {
    let s_from = make_pseudonymisation_factor(&pseudonymization_secret.0, &from_user.0);
    let s_to = make_pseudonymisation_factor(&pseudonymization_secret.0, &to_user.0);
    let k_from = make_decryption_factor(&encryption_secret.0, &from_session.0);
    let k_to = make_decryption_factor(&encryption_secret.0, &to_session.0);
    EncryptedPseudonym(rsk_from_to(&p.0, &s_from, &s_to, &k_from, &k_to))
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
#[wasm_bindgen(js_name = rekey)]
pub fn rekey(p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext, encryption_secret: &EncryptionSecret) -> EncryptedDataPoint {
    let k_from = make_decryption_factor(&encryption_secret.0, &from_session.0);
    let k_to = make_decryption_factor(&encryption_secret.0, &to_session.0);
    EncryptedDataPoint(rekey_from_to(&p.0, &k_from, &k_to))
}
