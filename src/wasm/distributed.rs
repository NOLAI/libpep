use crate::distributed::key_blinding::*;
use crate::distributed::systems::*;
use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::internal::arithmetic::ScalarNonZero;
use crate::wasm::arithmetic::*;
use crate::wasm::high_level::*;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

#[derive(Copy, Clone, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindingFactor)]
pub struct WASMBlindingFactor(BlindingFactor);

#[wasm_bindgen(js_class = "BlindingFactor")]
impl WASMBlindingFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindingFactor(BlindingFactor(x.0))
    }
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let x = BlindingFactor::random(&mut rng);
        WASMBlindingFactor(x)
    }
    #[wasm_bindgen(js_name = clone)]
    pub fn clone(&self) -> Self {
        WASMBlindingFactor(self.0.clone())
    }

    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMBlindingFactor> {
        BlindingFactor::decode_from_slice(&bytes.as_slice()).map(|x| WASMBlindingFactor(x))
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindingFactor> {
        BlindingFactor::decode_from_hex(hex).map(|x| WASMBlindingFactor(x))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedGlobalSecretKey)]
pub struct WASMBlindedGlobalSecretKey(BlindedGlobalSecretKey);

#[wasm_bindgen(js_class = "BlindedGlobalSecretKey")]
impl WASMBlindedGlobalSecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindedGlobalSecretKey(BlindedGlobalSecretKey(x.0))
    }

    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMBlindedGlobalSecretKey> {
        BlindedGlobalSecretKey::decode_from_slice(&bytes.as_slice())
            .map(|x| WASMBlindedGlobalSecretKey(x))
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindedGlobalSecretKey> {
        BlindedGlobalSecretKey::decode_from_hex(hex).map(|x| WASMBlindedGlobalSecretKey(x))
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionKeyShare)]
pub struct WASMSessionKeyShare(SessionKeyShare);

#[wasm_bindgen(js_class = "SessionKeyShare")]
impl WASMSessionKeyShare {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMSessionKeyShare(SessionKeyShare(x.0))
    }

    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<WASMSessionKeyShare> {
        SessionKeyShare::decode_from_slice(&bytes.as_slice()).map(|x| WASMSessionKeyShare(x))
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMSessionKeyShare> {
        SessionKeyShare::decode_from_hex(hex).map(|x| WASMSessionKeyShare(x))
    }
}

#[wasm_bindgen(js_name = makeBlindedGlobalSecretKey)]
pub fn wasm_make_blinded_global_secret_key(
    global_secret_key: &WASMGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> WASMBlindedGlobalSecretKey {
    // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
    // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
    // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    WASMBlindedGlobalSecretKey(
        make_blinded_global_secret_key(
            &GlobalSecretKey::from(ScalarNonZero::from(global_secret_key.0)),
            &bs,
        )
        .unwrap(),
    )
}

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PEPSystem)]
pub struct WASMPEPSystem(PEPSystem);

#[wasm_bindgen(js_class = PEPSystem)]
impl WASMPEPSystem {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonymisation_secret: &str,
        rekeying_secret: &str,
        blinding_factor: &WASMBlindingFactor,
    ) -> Self {
        Self(PEPSystem::new(
            PseudonymizationSecret::from(pseudonymisation_secret.as_bytes().into()),
            EncryptionSecret::from(rekeying_secret.as_bytes().into()),
            BlindingFactor(blinding_factor.0 .0),
        ))
    }

    #[wasm_bindgen(js_name = sessionKeyShare)]
    pub fn wasm_session_key_share(&self, context: &str) -> WASMSessionKeyShare {
        WASMSessionKeyShare(self.session_key_share(&EncryptionContext::from(context)))
    }

    #[wasm_bindgen(js_name = rekeyInfo)]
    pub fn wasm_rekey_info(&self, from_enc: &str, to_enc: &str) -> WASMRekeyInfo {
        WASMRekeyInfo::from(self.rekey_info(
            &EncryptionContext::from(from_enc),
            &EncryptionContext::from(to_enc),
        ))
    }

    #[wasm_bindgen(js_name = pseudonymizationInfo)]
    pub fn wasm_pseudonymization_info(
        &self,
        from_pseudo: &str,
        to_pseudo: &str,
        from_enc: &str,
        to_enc: &str,
    ) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo::from(self.pseudonymization_info(
            &PseudonymizationContext::from(from_pseudo),
            &PseudonymizationContext::from(to_pseudo),
            &EncryptionContext::from(from_enc),
            &EncryptionContext::from(to_enc),
        ))
    }

    #[wasm_bindgen(js_name = rekey)]
    pub fn wasm_rekey(
        &self,
        encrypted: &WASMEncryptedDataPoint,
        rekey_info: &WASMRekeyInfo,
    ) -> WASMEncryptedDataPoint {
        WASMEncryptedDataPoint::from(self.rekey(&encrypted.0, &RekeyInfo::from(rekey_info)))
    }

    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> WASMEncryptedPseudonym {
        WASMEncryptedPseudonym::from(
            self.pseudonymize(&encrypted.0, &PseudonymizationInfo::from(pseudo_info)),
        )
    }
}
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PEPClient)]
pub struct WASMPEPClient(PEPClient);
#[wasm_bindgen(js_class = PEPClient)]
impl WASMPEPClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        blinded_global_private_key: &WASMBlindedGlobalSecretKey,
        session_key_shares: Vec<WASMSessionKeyShare>,
    ) -> Self {
        // FIXME we do not pass a reference to the blinding factors vector, since WASM does not support references to arrays of structs
        // As a result, we have to clone the blinding factors BEFORE passing them to the function, so in javascript.
        // Simply by passing the blinding factors to this function will turn them into null pointers, so we cannot use them anymore in javascript.
        let session_key_shares: Vec<SessionKeyShare> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShare(x.0 .0))
            .collect();
        let blinded_key = blinded_global_private_key.0.clone();
        Self(PEPClient::new(
            BlindedGlobalSecretKey(blinded_key.0),
            &*session_key_shares,
        ))
    }
    #[wasm_bindgen(js_name = decryptPseudonym)]
    pub fn wasm_decrypt_pseudonym(&self, encrypted: &WASMEncryptedPseudonym) -> WASMPseudonym {
        WASMPseudonym::from(self.decrypt(&encrypted.0))
    }

    #[wasm_bindgen(js_name = decryptData)]
    pub fn wasm_decrypt_data(&self, encrypted: &WASMEncryptedDataPoint) -> WASMDataPoint {
        WASMDataPoint::from(self.decrypt(&encrypted.0))
    }

    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMDataPoint) -> WASMEncryptedDataPoint {
        let mut rng = rand::thread_rng();
        WASMEncryptedDataPoint::from(self.encrypt(&message.0, &mut rng))
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        WASMEncryptedPseudonym(EncryptedPseudonym::from(
            self.encrypt(&message.0, &mut rng).value,
        ))
    }
}

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = OfflinePEPClient)]
pub struct WASMOfflinePEPClient(OfflinePEPClient);

#[wasm_bindgen(js_class = OfflinePEPClient)]
impl WASMOfflinePEPClient {
    #[wasm_bindgen(constructor)]
    pub fn new(global_public_key: WASMGlobalPublicKey) -> Self {
        Self(OfflinePEPClient::new(GlobalPublicKey(
            *global_public_key.0.clone(),
        )))
    }
    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMDataPoint) -> WASMEncryptedDataPoint {
        let mut rng = rand::thread_rng();
        WASMEncryptedDataPoint::from(self.encrypt(&message.0, &mut rng))
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        WASMEncryptedPseudonym(EncryptedPseudonym::from(
            self.encrypt(&message.0, &mut rng).value,
        ))
    }
}
