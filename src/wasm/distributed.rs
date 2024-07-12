use rand_core::OsRng;
use wasm_bindgen::prelude::*;
use crate::arithmetic::*;
use crate::utils::*;
use crate::high_level::*;

#[wasm_bindgen]
pub struct BlindingFactor(ScalarNonZero);
#[wasm_bindgen]
pub struct BlindedGlobalSecretKey(ScalarNonZero);
#[wasm_bindgen]
pub struct SessionKeyShare(ScalarNonZero);

#[wasm_bindgen(js_name = makeBlindingFactor)]
pub fn make_blinding_factor() -> BlindingFactor {
    let mut rng = OsRng;
    BlindingFactor(ScalarNonZero::random(&mut rng))
}

#[wasm_bindgen(js_name = makeBlindedGlobalSecretKey)]
pub fn make_blinded_global_secret_key(global_secret_key: GlobalSecretKey, blinding_factors: Vec<BlindingFactor>) -> BlindedGlobalSecretKey {
    let x = blinding_factors.iter().fold(global_secret_key.0, |acc, x| acc * x.0);
    BlindedGlobalSecretKey(x)
}


#[wasm_bindgen]
pub struct PEPSystem {
    pseudonymisation_secret: PseudonymizationSecret,
    rekeying_secret: EncryptionSecret,
    blinding_factor: BlindingFactor,
}

#[wasm_bindgen]
impl PEPSystem {
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonymisation_secret: PseudonymizationSecret, rekeying_secret: EncryptionSecret, blinding_factor: BlindingFactor) -> Self {
        Self {
            pseudonymisation_secret,
            rekeying_secret,
            blinding_factor,
        }
    }

    #[wasm_bindgen(js_name = sessionKeyShare)]
    pub fn session_key_share(&self, context: &EncryptionContext) -> SessionKeyShare {
        let k = make_decryption_factor(&self.rekeying_secret, &context);
        k * &self.blinding_factor.invert()
    }

    #[wasm_bindgen(js_name = generateSessionKeys)]
    pub fn rekey(&self, p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext) -> EncryptedDataPoint {
        rekey(&p, from_session, to_session, &self.rekeying_secret)
    }
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(&self, p: &EncryptedPseudonym, from_context: &PseudonymizationContext, to_context: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext) -> EncryptedPseudonym {
        pseudonymize(&p, from_context, to_context, from_session, to_session, &self.pseudonymisation_secret, &self.rekeying_secret)
    }
    #[wasm_bindgen(js_name = decryptPseudonym)]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: EncryptedPseudonym) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(encrypted)
    }
    #[wasm_bindgen(js_name = decryptData)]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: EncryptedDataPoint) -> EncryptedDataPoint {
        rerandomize_encrypted(encrypted)
    }
}


#[wasm_bindgen]
pub struct PEPClient {
    session_secret_key: SessionSecretKey,
    session_public_key: SessionPublicKey,
}
#[wasm_bindgen]
impl PEPClient {
    #[wasm_bindgen(constructor)]
    pub fn new(blinded_global_private_key: BlindedGlobalSecretKey, session_key_shares: Vec<SessionKeyShare>) -> Self {
        let secret_key = SessionSecretKey(session_key_shares.iter().fold(blinded_global_private_key.0, |acc, x| acc * x.0));
        let public_key = SessionPublicKey(secret_key.0 * &G);
        Self {
            session_secret_key: secret_key,
            session_public_key: public_key,
        }
    }
    #[wasm_bindgen(js_name = decryptPseudonym)]
    pub fn decrypt_pseudonym(&self, p: &EncryptedPseudonym) -> Pseudonym {
        decrypt_pseudonym(&p, &self.session_secret_key)
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn decrypt_data(&self, data: &EncryptedDataPoint) -> DataPoint {
        decrypt_data(&data, &self.session_secret_key)
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn encrypt_data(&self, data: &DataPoint) -> EncryptedDataPoint {
        encrypt_data(data, &(self.session_public_key))
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn encrypt_pseudonym(&self, p: &Pseudonym) -> EncryptedPseudonym {
        encrypt_pseudonym(p, &(self.session_public_key))
    }

    #[wasm_bindgen(js_name = rerandomizeEncryptedPseudonym)]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: EncryptedPseudonym) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(encrypted)
    }

    #[wasm_bindgen(js_name = rerandomizeEncryptedData)]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: EncryptedDataPoint) -> EncryptedDataPoint {
        rerandomize_encrypted(encrypted)
    }
}
