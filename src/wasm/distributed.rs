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

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindingFactor)]
pub struct WASMBlindingFactor(pub WASMScalarNonZero);

#[wasm_bindgen(js_class = "BlindingFactor")]
impl WASMBlindingFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindingFactor(x)
    }
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let x = BlindingFactor::random(&mut rng);
        WASMBlindingFactor(WASMScalarNonZero::from(x.0))
    }

    #[wasm_bindgen(js_name = clone)]
    pub fn clone(&self) -> Self {
        WASMBlindingFactor(self.0.clone())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedGlobalSecretKey)]
pub struct WASMBlindedGlobalSecretKey(pub WASMScalarNonZero);

#[wasm_bindgen(js_class = "BlindedGlobalSecretKey")]
impl WASMBlindedGlobalSecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindedGlobalSecretKey(x)
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionKeyShare)]
pub struct WASMSessionKeyShare(pub WASMScalarNonZero);

#[wasm_bindgen(js_class = "SessionKeyShare")]
impl WASMSessionKeyShare {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMSessionKeyShare(x)
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
        .map(|x| BlindingFactor::from(x.0 .0))
        .collect();
    WASMBlindedGlobalSecretKey::from(WASMScalarNonZero::from(
        make_blinded_global_secret_key(
            &GlobalSecretKey::from(ScalarNonZero::from(global_secret_key.0)),
            &bs,
        )
        .unwrap()
        .0,
    ))
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
            BlindingFactor::from(blinding_factor.0 .0),
        ))
    }

    #[wasm_bindgen(js_name = sessionKeyShare)]
    pub fn wasm_session_key_share(&self, context: &str) -> WASMSessionKeyShare {
        WASMSessionKeyShare::from(WASMScalarNonZero::from(
            self.session_key_share(&EncryptionContext::from(context)).0,
        ))
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
        p: &WASMEncryptedDataPoint,
        rekey_info: &WASMRekeyInfo,
    ) -> WASMEncryptedDataPoint {
        WASMEncryptedDataPoint::from(self.rekey(&p.0, &RekeyInfo::from(rekey_info)))
    }

    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        p: &WASMEncryptedPseudonym,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> WASMEncryptedPseudonym {
        WASMEncryptedPseudonym::from(
            self.pseudonymize(&p.0, &PseudonymizationInfo::from(pseudonymization_info)),
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
            .map(|x| SessionKeyShare::from(x.0 .0))
            .collect();
        let blinded_key = blinded_global_private_key.0.clone();
        Self(PEPClient::new(
            BlindedGlobalSecretKey::from(blinded_key.0),
            &*session_key_shares,
        ))
    }
    #[wasm_bindgen(js_name = decryptPseudonym)]
    pub fn wasm_decrypt_pseudonym(&self, p: &WASMEncryptedPseudonym) -> WASMPseudonym {
        WASMPseudonym::from(self.decrypt(&p.0))
    }

    #[wasm_bindgen(js_name = decryptData)]
    pub fn wasm_decrypt_data(&self, data: &WASMEncryptedDataPoint) -> WASMDataPoint {
        WASMDataPoint::from(self.decrypt(&data.0))
    }

    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, data: &WASMDataPoint) -> WASMEncryptedDataPoint {
        let mut rng = rand::thread_rng();
        WASMEncryptedDataPoint::from(self.encrypt(&data.0, &mut rng))
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, p: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::thread_rng();
        WASMEncryptedPseudonym(EncryptedPseudonym::from(self.encrypt(&p.0, &mut rng).value))
    }
}
