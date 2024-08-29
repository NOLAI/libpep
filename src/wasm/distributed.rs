use wasm_bindgen::prelude::*;
use crate::wasm::arithmetic::*;
use crate::wasm::high_level::*;
use crate::distributed::*;
use crate::high_level::{EncryptionContext, EncryptionSecret, PseudonymizationContext, PseudonymizationSecret};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = BlindingFactor)]
pub struct WASMBlindingFactor(pub WASMScalarNonZero);
impl From<BlindingFactor> for WASMBlindingFactor {
    fn from(x: BlindingFactor) -> Self {
        WASMBlindingFactor(x.0.into())
    }
}
impl From<WASMBlindingFactor> for BlindingFactor {
    fn from(x: WASMBlindingFactor) -> Self {
        BlindingFactor(x.0.into())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = BlindedGlobalSecretKey)]
pub struct WASMBlindedGlobalSecretKey(pub WASMScalarNonZero);
impl From<BlindedGlobalSecretKey> for WASMBlindedGlobalSecretKey {
    fn from(x: BlindedGlobalSecretKey) -> Self {
        WASMBlindedGlobalSecretKey(x.0.into())
    }
}
impl From<WASMBlindedGlobalSecretKey> for BlindedGlobalSecretKey {
    fn from(x: WASMBlindedGlobalSecretKey) -> Self {
        BlindedGlobalSecretKey(x.0.into())
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = SessionKeyShare)]
pub struct WASMSessionKeyShare(pub WASMScalarNonZero);
impl From<SessionKeyShare> for WASMSessionKeyShare {
    fn from(x: SessionKeyShare) -> Self {
        WASMSessionKeyShare(x.0.into())
    }
}
impl From<WASMSessionKeyShare> for SessionKeyShare {
    fn from(x: WASMSessionKeyShare) -> Self {
        SessionKeyShare(x.0.into())
    }
}

#[wasm_bindgen(js_class = "BlindingFactor")]
impl WASMBlindingFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        BlindingFactor::new(x.into()).into()
    }
    #[wasm_bindgen(js_name = random)]
    pub fn random() -> Self {
        BlindingFactor::random().into()
    }

    #[wasm_bindgen(js_name = clone)]
    pub fn clone(&self) -> Self {
        WASMBlindingFactor(self.0.clone())
    }

}

#[wasm_bindgen(js_name = makeBlindedGlobalSecretKey)]
pub fn wasm_make_blinded_global_secret_key(global_secret_key: &WASMGlobalSecretKey, blinding_factors: Vec<WASMBlindingFactor>) -> WASMBlindedGlobalSecretKey {
    // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
    // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
    // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
    let bs = blinding_factors.as_slice().into_iter().map(|x| (*x).into()).collect();
    make_blinded_global_secret_key(&(*global_secret_key).into(), &bs).into()
}


#[wasm_bindgen(js_name = PEPSystem)]
pub struct WASMPEPSystem(PEPSystem);

#[wasm_bindgen(js_class = "PEPSystem")]
impl WASMPEPSystem {
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonymisation_secret: &str, rekeying_secret: &str, blinding_factor: &WASMBlindingFactor) -> Self {
        Self(PEPSystem::new(PseudonymizationSecret(pseudonymisation_secret.to_string()), EncryptionSecret(rekeying_secret.to_string()), (*blinding_factor).into()).into())
    }

    #[wasm_bindgen(js_name = sessionKeyShare)]
    pub fn session_key_share(&self, context: &str) -> WASMSessionKeyShare {
        self.0.session_key_share(&EncryptionContext(context.to_string())).into()
    }

    #[wasm_bindgen(js_name = rekey)]
    pub fn rekey(&self, p: &WASMEncryptedDataPoint, from_session: &str, to_session: &str) -> WASMEncryptedDataPoint {
        self.0.rekey(&(*p).into(), &EncryptionContext(from_session.to_string()), &(EncryptionContext(to_session.to_string()))).into()
    }
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn pseudonymize(&self, p: &WASMEncryptedPseudonym, from_context: &str, to_context: &str, from_session: &str, to_session: &str) -> WASMEncryptedPseudonym {
        self.0.pseudonymize(&(*p).into(), &PseudonymizationContext(from_context.to_string()), &PseudonymizationContext(to_context.to_string()), &EncryptionContext(from_session.to_string()), &(EncryptionContext(to_session.to_string()))).into()
    }

    #[cfg(not(feature = "elgamal2"))]
    #[wasm_bindgen(js_name = rerandomizePseudonym)]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: &WASMEncryptedPseudonym) -> WASMEncryptedPseudonym {
        self.0.rerandomize_encrypted_pseudonym((*encrypted).into()).into()
    }
    #[cfg(not(feature = "elgamal2"))]
    #[wasm_bindgen(js_name = rerandomizeData)]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: &WASMEncryptedDataPoint) -> WASMEncryptedDataPoint {
        self.0.rerandomize_encrypted_data_point((*encrypted).into()).into()
    }
}


#[wasm_bindgen(js_name = PEPClient)]
pub struct WASMPEPClient(PEPClient);
#[wasm_bindgen(js_class = "PEPClient")]
impl WASMPEPClient {
    #[wasm_bindgen(constructor)]
    pub fn new(blinded_global_private_key: &WASMBlindedGlobalSecretKey, session_key_shares: Vec<WASMSessionKeyShare>) -> Self {
        // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
        // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
        // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
        let session_key_shares = session_key_shares.as_slice().into_iter().map(|x| (*x).into()).collect();
        Self(PEPClient::new(blinded_global_private_key.clone().into(), session_key_shares))
    }
    #[wasm_bindgen(js_name = decryptPseudonym)]
    pub fn decrypt_pseudonym(&self, p: &WASMEncryptedPseudonym) -> WASMPseudonym {
        self.0.decrypt_pseudonym(&(*p).into()).into()
    }

    #[wasm_bindgen(js_name = decryptData)]
    pub fn decrypt_data(&self, data: &WASMEncryptedDataPoint) -> WASMDataPoint {
        self.0.decrypt_data(&(*data).into()).into()
    }

    #[wasm_bindgen(js_name = encryptData)]
    pub fn encrypt_data(&self, data: &WASMDataPoint) -> WASMEncryptedDataPoint {
        self.0.encrypt_data(&(*data).into()).into()
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn encrypt_pseudonym(&self, p: &WASMPseudonym) -> WASMEncryptedPseudonym {
        self.0.encrypt_pseudonym(&(*p).into()).into()
    }

    #[cfg(not(feature = "elgamal2"))]
    #[wasm_bindgen(js_name = rerandomizePseudonym)]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: &WASMEncryptedPseudonym) -> WASMEncryptedPseudonym {
        self.0.rerandomize_encrypted_pseudonym((*encrypted).into()).into()
    }

    #[cfg(not(feature = "elgamal2"))]
    #[wasm_bindgen(js_name = rerandomizeData)]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: &WASMEncryptedDataPoint) -> WASMEncryptedDataPoint {
        self.0.rerandomize_encrypted_data_point((*encrypted).into()).into()
    }
}
