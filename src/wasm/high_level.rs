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
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = GlobalSecretKey)]
pub struct WASMGlobalSecretKey(pub WASMScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionPublicKey)]
pub struct WASMSessionPublicKey(pub WASMGroupElement);
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = GlobalPublicKey)]
pub struct WASMGlobalPublicKey(pub WASMGroupElement);


#[derive(Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymizationSecret)]
pub struct WASMPseudonymizationSecret(PseudonymizationSecret);
#[derive(Clone, Debug, From)]
#[wasm_bindgen(js_name = EncryptionSecret)]
pub struct WASMEncryptionSecret(EncryptionSecret);

#[wasm_bindgen(js_class = "PseudonymizationSecret")]
impl WASMPseudonymizationSecret {
    #[wasm_bindgen(constructor)]
    pub fn from(data: Vec<u8>) -> Self {
        Self(PseudonymizationSecret::from(data))
    }
}
#[wasm_bindgen(js_class = "EncryptionSecret")]
impl WASMEncryptionSecret {
    #[wasm_bindgen(constructor)]
    pub fn from(data: Vec<u8>) -> Self {
        Self(EncryptionSecret::from(data))
    }
}

#[wasm_bindgen(js_name = Pseudonym)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMPseudonym(pub(crate) Pseudonym);
#[wasm_bindgen(js_name = DataPoint)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMDataPoint(pub(crate) DataPoint);

#[wasm_bindgen(js_name = EncryptedPseudonym)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMEncryptedPseudonym(pub(crate) EncryptedPseudonym);
#[wasm_bindgen(js_name = EncryptedDataPoint)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMEncryptedDataPoint(pub(crate) EncryptedDataPoint);

#[wasm_bindgen(js_class = "Pseudonym")]
impl WASMPseudonym {
    #[wasm_bindgen(constructor)]
    pub fn from_point(x: WASMGroupElement) -> Self {
        Self(Pseudonym::from_point(GroupElement::from(x)))
    }
    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(&self) -> WASMGroupElement {
        self.0.value.into()
    }
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self(Pseudonym::random(&mut rng))
    }
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
    }
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<Self> {
        Pseudonym::decode_from_slice(&bytes.as_slice()).map(|x| Self(x))
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Pseudonym::decode_from_hex(hex).map(|x| Self(x))
    }
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> Self {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Pseudonym::from_hash(&arr).into()
    }
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data);
        Self(Pseudonym::from_bytes(&arr))
    }
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        self.0.to_bytes().map(|x| x.to_vec())
    }
}

#[wasm_bindgen(js_class = "DataPoint")]
impl WASMDataPoint {
    #[wasm_bindgen(constructor)]
    pub fn from_point(x: WASMGroupElement) -> Self {
        Self (DataPoint::from_point(GroupElement::from(x)))
    }
    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(&self) -> WASMGroupElement {
        self.0.value.into()
    }
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self(DataPoint::random(&mut rng))
    }
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.encode_to_hex()
    }
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<Self> {
        DataPoint::decode_from_slice(&bytes.as_slice()).map(|x| Self(x))
    }
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        DataPoint::decode_from_hex(hex).map(|x| Self(x))
    }
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> Self {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        DataPoint::from_hash(&arr).into()
    }
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data);
        Self(DataPoint::from_bytes(&arr))
    }
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        self.0.to_bytes().map(|x| x.to_vec())
    }
}

#[wasm_bindgen(js_class = "EncryptedPseudonym")]
impl WASMEncryptedPseudonym {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        WASMEncryptedPseudonym(EncryptedPseudonym::from(ElGamal::from(x)))
    }
}

#[wasm_bindgen(js_class = "EncryptedDataPoint")]
impl WASMEncryptedDataPoint {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        WASMEncryptedDataPoint(EncryptedDataPoint::from(ElGamal::from(x)))
    }
}

// We cannot return a tuple from a wasm_bindgen function, so we return a struct instead
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalKeyPair)]
pub struct WASMGlobalKeyPair {
    pub public: WASMGlobalPublicKey,
    pub secret: WASMGlobalSecretKey,
}

#[derive(Copy, Clone, Debug)]
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
    encryption_secret: &WASMEncryptionSecret,
) -> WASMSessionKeyPair {
    let (public, secret) = make_session_keys(
        &GlobalSecretKey(*global.0),
        &EncryptionContext::from(context),
        &encryption_secret.0,
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
    WASMEncryptedPseudonym(
        encrypt(&p.0, &SessionPublicKey::from(GroupElement::from(pk.0)), &mut rng)
    )
}

/// Decrypt an encrypted pseudonym
#[wasm_bindgen(js_name = decryptPseudonym)]
pub fn wasm_decrypt_pseudonym(
    p: &WASMEncryptedPseudonym,
    sk: &WASMSessionSecretKey,
) -> WASMPseudonym {
    WASMPseudonym(
        decrypt(&p.0, &SessionSecretKey::from(ScalarNonZero::from(sk.0)), )
    )
}

/// Encrypt a data point
#[wasm_bindgen(js_name = encryptData)]
pub fn wasm_encrypt_data(
    data: &WASMDataPoint,
    pk: &WASMSessionPublicKey,
) -> WASMEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    WASMEncryptedDataPoint(
        encrypt(&data.0,
            &SessionPublicKey::from(GroupElement::from(pk.0)),
            &mut rng,
        )
    )
}

/// Decrypt an encrypted data point
#[wasm_bindgen(js_name = decryptData)]
pub fn wasm_decrypt_data(
    data: &WASMEncryptedDataPoint,
    sk: &WASMSessionSecretKey,
) -> WASMDataPoint {
    WASMDataPoint(
        decrypt(
            &EncryptedDataPoint::from(ElGamal::from(data.value)),
            &SessionSecretKey::from(ScalarNonZero::from(sk.0)),
        )
    )
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = RerandomizeFactor)]
pub struct WASMRerandomizeFactor(RerandomizeFactor);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = ReshuffleFactor)]
pub struct WASMReshuffleFactor(ReshuffleFactor);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = RekeyFactor)]
pub struct WASMRekeyFactor(RekeyFactor);

#[cfg(not(feature = "elgamal2"))]
#[wasm_bindgen(js_name = rerandomizePseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(WASMElGamal::from(
        rerandomize(
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
        rerandomize(
            &EncryptedDataPoint::from(ElGamal::from(encrypted.value)),
            &mut rng,
        )
        .value,
    ))
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = RSKFactors)]
pub struct WASMRSKFactors {
    pub s: WASMReshuffleFactor,
    pub k: WASMRekeyFactor,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymizationInfo)]
pub struct WASMPseudonymizationInfo(pub WASMRSKFactors);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = RekeyInfo)]
pub struct WASMRekeyInfo(pub WASMRekeyFactor);

#[wasm_bindgen(js_class = PseudonymizationInfo)]
impl WASMPseudonymizationInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        from_pseudo_context: &str,
        to_pseudo_context: &str,
        from_enc_context: &str,
        to_enc_context: &str,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let x = PseudonymizationInfo::new(
            &PseudonymizationContext::from(from_pseudo_context),
            &PseudonymizationContext::from(to_pseudo_context),
            &EncryptionContext::from(from_enc_context),
            &EncryptionContext::from(to_enc_context),
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );
        let s = WASMReshuffleFactor(x.s);
        let k = WASMRekeyFactor(x.k);
        WASMPseudonymizationInfo(WASMRSKFactors { s, k })
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMPseudonymizationInfo(WASMRSKFactors {
            s: WASMReshuffleFactor(ReshuffleFactor(self.0.s.0.0.invert())),
            k: WASMRekeyFactor(RekeyFactor(self.0.k.0.0.invert())),
        })
    }
}

#[wasm_bindgen(js_class = RekeyInfo)]
impl WASMRekeyInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(from_enc_context: &str, to_enc_context: &str, encryption_secret: &WASMEncryptionSecret) -> Self {
        let x = RekeyInfo::new(
            &EncryptionContext::from(from_enc_context),
            &EncryptionContext::from(to_enc_context),
            &encryption_secret.0
        );
        WASMRekeyInfo(WASMRekeyFactor(x))
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMRekeyInfo(WASMRekeyFactor(RekeyFactor(self.0.0.0.invert())))
    }
    #[wasm_bindgen(js_name = fromPseudoInfo)]
    pub fn from_pseudo_info(x: &WASMPseudonymizationInfo) -> Self {
        WASMRekeyInfo(x.0.k)
    }
}

impl From<PseudonymizationInfo> for WASMPseudonymizationInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        let s = WASMReshuffleFactor(x.s);
        let k = WASMRekeyFactor(x.k);
        WASMPseudonymizationInfo(WASMRSKFactors { s, k })
    }
}

impl From<&WASMPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &WASMPseudonymizationInfo) -> Self {
        let s = x.s.0;
        let k = x.k.0;
        PseudonymizationInfo { s, k }
    }
}

impl From<RekeyInfo> for WASMRekeyInfo {
    fn from(x: RekeyInfo) -> Self {
        WASMRekeyInfo(WASMRekeyFactor(x))
    }
}

impl From<&WASMRekeyInfo> for RekeyInfo {
    fn from(x: &WASMRekeyInfo) -> Self {
        Self(x.0.0.0)
    }
}

/// Pseudonymize an encrypted pseudonym, from one context to another context
#[wasm_bindgen(js_name = pseudonymize)]
pub fn wasm_pseudonymize(
    p: &WASMEncryptedPseudonym,
    pseudo_info: &WASMPseudonymizationInfo,
) -> WASMEncryptedPseudonym {
    let x = pseudonymize(
        &EncryptedPseudonym::from(p.value),
        &PseudonymizationInfo::from(pseudo_info),
    );
    WASMEncryptedPseudonym(x)
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
#[wasm_bindgen(js_name = rekeyData)]
pub fn wasm_rekey_data(
    p: &WASMEncryptedDataPoint,
    rekey_info: &WASMRekeyInfo,
) -> WASMEncryptedDataPoint {
    let x = rekey(
        &EncryptedDataPoint::from(p.value),
        &RekeyInfo::from(rekey_info),
    );
    WASMEncryptedDataPoint(x)
}

#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    pseudonymization_info: &WASMPseudonymizationInfo,
) -> Box<[WASMEncryptedPseudonym]> {
    let mut rng = rand::thread_rng();
    let mut encrypted = encrypted.iter().map(|x| x.0).collect::<Vec<_>>();
    pseudonymize_batch(&mut encrypted, &PseudonymizationInfo::from(pseudonymization_info), &mut rng)
        .iter()
        .map(|x| WASMEncryptedPseudonym(*x))
        .collect()
}

#[wasm_bindgen(js_name = rekeyBatch)]
pub fn wasm_rekey_batch(
    encrypted: Vec<WASMEncryptedDataPoint>,
    rekey_info: &WASMRekeyInfo,
) -> Box<[WASMEncryptedDataPoint]> {
    let mut rng = rand::thread_rng();
    let mut encrypted = encrypted.iter().map(|x| x.0).collect::<Vec<_>>();
    rekey_batch(&mut encrypted, &RekeyInfo::from(rekey_info), &mut rng)
        .iter()
        .map(|x| WASMEncryptedDataPoint(*x))
        .collect()
}

// TODO implement WASM batch transcryption (data types are inconvenient)
//
// #[wasm_bindgen]
// #[derive(Clone)]
// pub struct TranscryptionData {
//     pub pseudonyms: Box<[WASMEncryptedPseudonym]>,
//     pub data_points: Box<[WASMEncryptedDataPoint]>
// }
// #[wasm_bindgen(js_name = transcryptBatch)]
// pub fn wasm_transcrypt_batch(
//     data: Box<[TranscryptionData]>,
//     transcryption_info: &WASMPseudonymizationInfo,
// ) -> Box<[TranscryptionData]> {
//     let mut rng = rand::thread_rng();
//
//     let mut transcryption_data = data.iter().map(|x| {
//         let pseudonyms = x.pseudonyms.iter().map(|x| x.0).collect();
//         let data_points = x.data_points.iter().map(|x| x.0).collect();
//         (pseudonyms, data_points)
//     }).collect();
//
//     let transcrypted = transcrypt_batch(
//         &mut transcryption_data,
//         &transcryption_info.into(),
//         &mut rng,
//     );
//
//     transcrypted.iter().map(|(pseudonyms, data_points)| {
//         let pseudonyms = pseudonyms.iter().map(|x| WASMEncryptedPseudonym(*x)).collect();
//         let data_points = data_points.iter().map(|x| WASMEncryptedDataPoint(*x)).collect();
//         TranscryptionData { pseudonyms, data_points }
//     }).collect()
// }
