use crate::arithmetic::{GroupElement, ScalarNonZero};
use crate::elgamal::ElGamal;
use crate::wasm::arithmetic::{WASMGroupElement, WASMScalarNonZero};
use crate::wasm::elgamal::WASMElGamal;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::wasm_bindgen;
use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionSecretKey)]
pub struct WASMSessionSecretKey(pub WASMScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = GlobalSecretKey)]
pub struct WASMGlobalSecretKey(pub WASMScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionPublicKey)]
pub struct WASMSessionPublicKey(pub WASMGroupElement);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = GlobalPublicKey)]
pub struct WASMGlobalPublicKey(pub WASMGroupElement);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = Pseudonym)]
pub struct WASMPseudonym {
    pub value: WASMGroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = DataPoint)]
pub struct WASMDataPoint {
    pub value: WASMGroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = EncryptedPseudonym)]
pub struct WASMEncryptedPseudonym {
    pub value: WASMElGamal,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = EncryptedDataPoint)]
pub struct WASMEncryptedDataPoint {
    pub value: WASMElGamal,
}

#[wasm_bindgen(js_class = "Pseudonym")]
impl WASMPseudonym {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        WASMPseudonym { value: x }
    }
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let x = Pseudonym::random(&mut rng);
        WASMPseudonym::from(WASMGroupElement::from(x.value))
    }
}
#[wasm_bindgen(js_class = "DataPoint")]
impl WASMDataPoint {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        WASMDataPoint { value: x }
    }
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let x = DataPoint::random(&mut rng);
        WASMDataPoint::from(WASMGroupElement::from(x.value))
    }
}

#[wasm_bindgen(js_class = "EncryptedPseudonym")]
impl WASMEncryptedPseudonym {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        WASMEncryptedPseudonym::from(x)
    }
}

#[wasm_bindgen(js_class = "EncryptedDataPoint")]
impl WASMEncryptedDataPoint {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        WASMEncryptedDataPoint::from(x)
    }
}

// We cannot return a tuple from a wasm_bindgen function, so we return a struct instead
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = GlobalKeyPair)]
pub struct WASMGlobalKeyPair {
    pub public: WASMGlobalPublicKey,
    pub secret: WASMGlobalSecretKey,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = SessionKeyPair)]
pub struct WASMSessionKeyPair {
    pub public: WASMSessionPublicKey,
    pub secret: WASMSessionSecretKey,
}

/// Generate a new global key pair
#[wasm_bindgen(js_name = makeGlobalKeys)]
pub fn wasm_make_global_keys() -> WASMGlobalKeyPair {
    let mut rng = rand::thread_rng();
    let (public, secret) = make_global_keys(&mut rng);
    WASMGlobalKeyPair {
        public: WASMGlobalPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMGlobalSecretKey::from(WASMScalarNonZero::from(secret.0)),
    }
}

/// Generate a subkey from a global secret key, a context, and an encryption secret
#[wasm_bindgen(js_name = makeSessionKeys)]
pub fn wasm_make_session_keys(
    global: &WASMGlobalSecretKey,
    context: &str,
    encryption_secret: Vec<u8>,
) -> WASMSessionKeyPair {
    let (public, secret) = make_session_keys(
        &GlobalSecretKey(***global),
        &EncryptionContext::from(context),
        &EncryptionSecret::from(encryption_secret),
    );
    WASMSessionKeyPair {
        public: WASMSessionPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMSessionSecretKey::from(WASMScalarNonZero::from(secret.0)),
    }
}

/// Encrypt a pseudonym
#[wasm_bindgen(js_name = encryptPseudonym)]
pub fn wasm_encrypt_pseudonym(
    p: &WASMPseudonym,
    pk: &WASMSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(WASMElGamal::from(
        encrypt(
            &Pseudonym::from(GroupElement::from(p.value)),
            &SessionPublicKey::from(GroupElement::from(pk.0)),
            &mut rng,
        )
        .value,
    ))
}

/// Decrypt an encrypted pseudonym
#[wasm_bindgen(js_name = decryptPseudonym)]
pub fn wasm_decrypt_pseudonym(
    p: &WASMEncryptedPseudonym,
    sk: &WASMSessionSecretKey,
) -> WASMPseudonym {
    WASMPseudonym::from(WASMGroupElement::from(
        decrypt(
            &EncryptedPseudonym::from(ElGamal::from(p.value)),
            &SessionSecretKey::from(ScalarNonZero::from(sk.0)),
        )
        .value,
    ))
}

/// Encrypt a data point
#[wasm_bindgen(js_name = encryptData)]
pub fn wasm_encrypt_data(
    data: &WASMDataPoint,
    pk: &WASMSessionPublicKey,
) -> WASMEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    WASMEncryptedDataPoint::from(WASMElGamal::from(
        encrypt(
            &DataPoint::from(GroupElement::from(data.value)),
            &SessionPublicKey::from(GroupElement::from(pk.0)),
            &mut rng,
        )
        .value,
    ))
}

/// Decrypt an encrypted data point
#[wasm_bindgen(js_name = decryptData)]
pub fn wasm_decrypt_data(
    data: &WASMEncryptedDataPoint,
    sk: &WASMSessionSecretKey,
) -> WASMDataPoint {
    WASMDataPoint::from(WASMGroupElement::from(
        decrypt(
            &EncryptedDataPoint::from(ElGamal::from(data.value)),
            &SessionSecretKey::from(ScalarNonZero::from(sk.0)),
        )
        .value,
    ))
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = RerandomizeFactor)]
pub struct WASMRerandomizeFactor(pub WASMScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = ReshuffleFactor)]
pub struct WASMReshuffleFactor(pub WASMScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = RekeyFactor)]
pub struct WASMRekeyFactor(pub WASMScalarNonZero);

#[cfg(not(feature = "elgamal2"))]
#[wasm_bindgen(js_name = rerandomizePseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(WASMElGamal::from(
        rerandomize_encrypted_pseudonym(
            &EncryptedPseudonym::from(ElGamal::from(encrypted.value)),
            &mut rng,
        )
        .value,
    ))
}

#[cfg(not(feature = "elgamal2"))]
#[wasm_bindgen(js_name = rerandomizeData)]
pub fn wasm_rerandomize_encrypted(encrypted: &WASMEncryptedDataPoint) -> WASMEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    WASMEncryptedDataPoint::from(WASMElGamal::from(
        rerandomize_encrypted(
            &EncryptedDataPoint::from(ElGamal::from(encrypted.value)),
            &mut rng,
        )
        .value,
    ))
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = Reshuffle2Factors)]
pub struct WASMReshuffle2Factors {
    pub from: WASMReshuffleFactor,
    pub to: WASMReshuffleFactor,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = Rekey2Factors)]
pub struct WASMRekey2Factors {
    pub from: WASMRekeyFactor,
    pub to: WASMRekeyFactor,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = RSK2Factors)]
pub struct WASMRSK2Factors {
    pub s: WASMReshuffle2Factors,
    pub k: WASMRekey2Factors,
}

#[wasm_bindgen(js_class = Reshuffle2Factors)]
impl WASMReshuffle2Factors {
    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMReshuffle2Factors {
            from: self.to.clone(),
            to: self.from.clone(),
        }
    }
}

#[wasm_bindgen(js_class = Rekey2Factors)]
impl WASMRekey2Factors {
    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMRekey2Factors {
            from: self.to.clone(),
            to: self.from.clone(),
        }
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymizationInfo)]
pub struct WASMPseudonymizationInfo(pub WASMRSK2Factors);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = RekeyInfo)]
pub struct WASMRekeyInfo(pub WASMRekey2Factors);

#[wasm_bindgen(js_class = PseudonymizationInfo)]
impl WASMPseudonymizationInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        from_pseudo_context: &str,
        to_pseudo_context: &str,
        from_enc_context: &str,
        to_enc_context: &str,
        pseudonymization_secret: &str,
        encryption_secret: &str,
    ) -> Self {
        let x = PseudonymizationInfo::new(
            &PseudonymizationContext::from(from_pseudo_context),
            &PseudonymizationContext::from(to_pseudo_context),
            &EncryptionContext::from(from_enc_context),
            &EncryptionContext::from(to_enc_context),
            &PseudonymizationSecret::from(pseudonymization_secret.as_bytes().to_vec()),
            &EncryptionSecret::from(encryption_secret.as_bytes().to_vec()),
        );
        let k = WASMRekey2Factors {
            from: WASMRekeyFactor(WASMScalarNonZero::from(x.k.from.0)),
            to: WASMRekeyFactor(WASMScalarNonZero::from(x.k.to.0)),
        };
        let s = WASMReshuffle2Factors {
            from: WASMReshuffleFactor(WASMScalarNonZero::from(x.s.from.0)),
            to: WASMReshuffleFactor(WASMScalarNonZero::from(x.s.to.0)),
        };
        WASMPseudonymizationInfo(WASMRSK2Factors { s, k })
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMPseudonymizationInfo(WASMRSK2Factors {
            s: self.0.s.rev(),
            k: self.0.k.rev(),
        })
    }
}

#[wasm_bindgen(js_class = RekeyInfo)]
impl WASMRekeyInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(from_enc_context: &str, to_enc_context: &str, encryption_secret: &str) -> Self {
        let x = RekeyInfo::new(
            &EncryptionContext::from(from_enc_context),
            &EncryptionContext::from(to_enc_context),
            &EncryptionSecret::from(encryption_secret.as_bytes().into()),
        );
        let k = WASMRekey2Factors {
            from: WASMRekeyFactor(WASMScalarNonZero::from(x.from.0)),
            to: WASMRekeyFactor(WASMScalarNonZero::from(x.to.0)),
        };
        WASMRekeyInfo(k)
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMRekeyInfo(self.0.rev())
    }
    #[wasm_bindgen(js_name = fromPseudoInfo)]
    pub fn from_pseudo_info(x: &WASMPseudonymizationInfo) -> Self {
        WASMRekeyInfo(x.0.k)
    }
}

impl From<PseudonymizationInfo> for WASMPseudonymizationInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        let k = WASMRekey2Factors {
            from: WASMRekeyFactor(WASMScalarNonZero::from(x.k.from.0)),
            to: WASMRekeyFactor(WASMScalarNonZero::from(x.k.to.0)),
        };
        let s = WASMReshuffle2Factors {
            from: WASMReshuffleFactor(WASMScalarNonZero::from(x.s.from.0)),
            to: WASMReshuffleFactor(WASMScalarNonZero::from(x.s.to.0)),
        };
        WASMPseudonymizationInfo(WASMRSK2Factors { s, k })
    }
}

impl From<&WASMPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &WASMPseudonymizationInfo) -> Self {
        let k = Rekey2Factors {
            from: RekeyFactor::from(ScalarNonZero::from(x.0.k.from.0)),
            to: RekeyFactor::from(ScalarNonZero::from(x.0.k.to.0)),
        };
        let s = Reshuffle2Factors {
            from: ReshuffleFactor::from(ScalarNonZero::from(x.0.s.from.0)),
            to: ReshuffleFactor::from(ScalarNonZero::from(x.0.s.to.0)),
        };
        PseudonymizationInfo { s, k }
    }
}

impl From<RekeyInfo> for WASMRekeyInfo {
    fn from(x: RekeyInfo) -> Self {
        let k = WASMRekey2Factors {
            from: WASMRekeyFactor(WASMScalarNonZero::from(x.from.0)),
            to: WASMRekeyFactor(WASMScalarNonZero::from(x.to.0)),
        };
        WASMRekeyInfo(k)
    }
}

impl From<&WASMRekeyInfo> for RekeyInfo {
    fn from(x: &WASMRekeyInfo) -> Self {
        RekeyInfo {
            from: RekeyFactor::from(ScalarNonZero::from(x.0.from.0)),
            to: RekeyFactor::from(ScalarNonZero::from(x.0.to.0)),
        }
    }
}

/// Pseudonymize an encrypted pseudonym, from one context to another context
#[wasm_bindgen(js_name = pseudonymize)]
pub fn wasm_pseudonymize(
    p: &WASMEncryptedPseudonym,
    pseudo_info: &WASMPseudonymizationInfo,
) -> WASMEncryptedPseudonym {
    let x = pseudonymize(
        &EncryptedPseudonym::from(ElGamal::from(p.value)),
        &PseudonymizationInfo::from(pseudo_info),
    );
    WASMEncryptedPseudonym::from(WASMElGamal::from(x.value))
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
#[wasm_bindgen(js_name = rekeyData)]
pub fn wasm_rekey_data(
    p: &WASMEncryptedDataPoint,
    rekey_info: &WASMRekeyInfo,
) -> WASMEncryptedDataPoint {
    let x = rekey(
        &EncryptedDataPoint::from(ElGamal::from(p.value)),
        &RekeyInfo::from(rekey_info),
    );
    WASMEncryptedDataPoint::from(WASMElGamal::from(x.value))
}
