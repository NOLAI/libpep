use std::ops::Deref;
use wasm_bindgen::prelude::wasm_bindgen;
use crate::high_level::*;
use crate::wasm::arithmetic::{WASMGroupElement, WASMScalarNonZero};
use crate::wasm::elgamal::WASMElGamal;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = SessionSecretKey)]
pub struct WASMSessionSecretKey(pub WASMScalarNonZero);

impl From<SessionSecretKey> for WASMSessionSecretKey {
    fn from(x: SessionSecretKey) -> Self {
        WASMSessionSecretKey(x.0.into())
    }
}
impl From<WASMSessionSecretKey> for SessionSecretKey {
    fn from(x: WASMSessionSecretKey) -> Self {
        SessionSecretKey(x.0.into())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = GlobalSecretKey)]
pub struct WASMGlobalSecretKey(pub WASMScalarNonZero);
impl From<GlobalSecretKey> for WASMGlobalSecretKey {
    fn from(x: GlobalSecretKey) -> Self {
        WASMGlobalSecretKey(x.0.into())
    }
}
impl From<WASMGlobalSecretKey> for GlobalSecretKey {
    fn from(x: WASMGlobalSecretKey) -> Self {
        GlobalSecretKey(x.0.into())
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = SessionPublicKey)]
pub struct WASMSessionPublicKey(pub WASMGroupElement);
impl From<SessionPublicKey> for WASMSessionPublicKey {
    fn from(x: SessionPublicKey) -> Self {
        WASMSessionPublicKey(x.0.into())
    }
}
impl From<WASMSessionPublicKey> for SessionPublicKey {
    fn from(x: WASMSessionPublicKey) -> Self {
        SessionPublicKey(x.0.into())
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = GlobalPublicKey)]
pub struct WASMGlobalPublicKey(pub WASMGroupElement);
impl From<GlobalPublicKey> for WASMGlobalPublicKey {
    fn from(x: GlobalPublicKey) -> Self {
        WASMGlobalPublicKey(x.0.into())
    }
}
impl From<WASMGlobalPublicKey> for GlobalPublicKey {
    fn from(x: WASMGlobalPublicKey) -> Self {
        GlobalPublicKey(x.0.into())
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = Pseudonym)]
pub struct WASMPseudonym {
    pub value: WASMGroupElement
}
#[wasm_bindgen(js_class = "Pseudonym")]
impl WASMPseudonym {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        WASMPseudonym {
            value: x
        }
    }
    #[wasm_bindgen]
    pub fn random() -> Self {
        Pseudonym::random().into()
    }
}
impl Deref for WASMPseudonym {
    type Target = WASMGroupElement;
    fn deref(&self) -> &Self::Target { &self.value }
}
impl From<Pseudonym> for WASMPseudonym {
    fn from(x: Pseudonym) -> Self {
        WASMPseudonym {
            value: x.value.into()
        }
    }
}
impl From<WASMPseudonym> for Pseudonym {
    fn from(x: WASMPseudonym) -> Self {
        Pseudonym { value: x.value.into()}
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = DataPoint)]
pub struct WASMDataPoint {
    pub value: WASMGroupElement
}

impl Deref for WASMDataPoint {
    type Target = WASMGroupElement;
    fn deref(&self) -> &Self::Target { &self.value }
}

#[wasm_bindgen(js_class = "DataPoint")]
impl WASMDataPoint {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMGroupElement) -> Self {
        WASMDataPoint {
            value: x
        }
    }
}

impl From<WASMDataPoint> for DataPoint {
    fn from(x: WASMDataPoint) -> Self {
        DataPoint { value: x.value.into() }
    }

}
impl From<DataPoint> for WASMDataPoint {
    fn from(x: DataPoint) -> Self {
        WASMDataPoint {
            value: x.value.into()
        }
    }
}


#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = EncryptedPseudonym)]
pub struct WASMEncryptedPseudonym {
    pub value: WASMElGamal
}
impl From<WASMEncryptedPseudonym> for EncryptedPseudonym {
    fn from(x: WASMEncryptedPseudonym) -> Self {
        EncryptedPseudonym {
            value : x.value.into()
        }
    }

}
impl From<EncryptedPseudonym> for WASMEncryptedPseudonym {
    fn from(x: EncryptedPseudonym) -> Self {
        WASMEncryptedPseudonym {
            value: x.value.into()
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[wasm_bindgen(js_name = EncryptedDataPoint)]
pub struct WASMEncryptedDataPoint {
    pub value: WASMElGamal
}
impl From<WASMEncryptedDataPoint> for EncryptedDataPoint {
    fn from(x: WASMEncryptedDataPoint) -> Self {
        EncryptedDataPoint { value: x.value.into() }
    }

}
impl From<EncryptedDataPoint> for WASMEncryptedDataPoint {
    fn from(x: EncryptedDataPoint) -> Self {
        WASMEncryptedDataPoint {
            value: x.value.into()
        }
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
    let (public, secret) = make_global_keys();
    WASMGlobalKeyPair {
        public: public.into(),
        secret: secret.into(),
    }
}

/// Generate a subkey from a global secret key, a context, and an encryption secret
#[wasm_bindgen(js_name = makeSessionKeys)]
pub fn wasm_make_session_keys(global: &WASMGlobalSecretKey, context: &str, encryption_secret: &str) -> WASMSessionKeyPair {
    let (public, secret) = make_session_keys(&(*global).into(), &EncryptionContext(context.to_string()), &EncryptionSecret(encryption_secret.to_string()));
    WASMSessionKeyPair {
        public: public.into(),
        secret: secret.into(),
    }
}

/// Encrypt a pseudonym
#[wasm_bindgen(js_name = encryptPseudonym)]
pub fn wasm_encrypt_pseudonym(p: &WASMPseudonym, pk: &WASMSessionPublicKey) -> WASMEncryptedPseudonym {
    encrypt_pseudonym(&(*p).into(), &(*pk).into()).into()
}

/// Decrypt an encrypted pseudonym
#[wasm_bindgen(js_name = decryptPseudonym)]
pub fn wasm_decrypt_pseudonym(p: &WASMEncryptedPseudonym, sk: &WASMSessionSecretKey) -> WASMPseudonym {
    decrypt_pseudonym(&(*p).into(), &(*sk).into()).into()
}

/// Encrypt a data point
#[wasm_bindgen(js_name = encryptData)]
pub fn wasm_encrypt_data(data: &WASMDataPoint, pk: &WASMSessionPublicKey) -> WASMEncryptedDataPoint {
    encrypt_data(&(*data).into(), &(*pk).into()).into()
}

/// Decrypt an encrypted data point
#[wasm_bindgen(js_name = decryptData)]
pub fn wasm_decrypt_data(data: &WASMEncryptedDataPoint, sk: &WASMSessionSecretKey) -> WASMDataPoint {
    decrypt_data(&(*data).into(), &(*sk).into()).into()
}

/// Rerandomize the ciphertext of an encrypted pseudonym
#[cfg(not(feature = "elgamal2"))]
#[wasm_bindgen(js_name = rerandomizePseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(encrypted: WASMEncryptedPseudonym) -> WASMEncryptedPseudonym {
    rerandomize_encrypted_pseudonym(encrypted.into()).into()
}

/// Rerandomize the ciphertext of an encrypted data point
#[cfg(not(feature = "elgamal2"))]
#[wasm_bindgen(js_name = rerandomizeData)]
pub fn wasm_rerandomize_encrypted(encrypted: WASMEncryptedDataPoint) -> WASMEncryptedDataPoint {
    rerandomize_encrypted(encrypted.into()).into()
}

/// Pseudonymize an encrypted pseudonym, from one context to another context
#[wasm_bindgen(js_name = pseudonymize)]
pub fn wasm_pseudonymize(p: &WASMEncryptedPseudonym, from_user: &str, to_user: &str, from_session: &str, to_session: &str, pseudonymization_secret: &str, encryption_secret: &str) -> WASMEncryptedPseudonym {
    pseudonymize(&(*p).into(), &PseudonymizationContext(from_user.to_string()), &PseudonymizationContext(to_user.to_string()), &EncryptionContext(from_session.to_string()), &EncryptionContext(to_session.to_string()), &PseudonymizationSecret(pseudonymization_secret.to_string()), &EncryptionSecret(encryption_secret.to_string())).into()
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
#[wasm_bindgen(js_name = rekeyData)]
pub fn wasm_rekey_data(p: &WASMEncryptedDataPoint, from_session: &str, to_session: &str, encryption_secret: &str) -> WASMEncryptedDataPoint {
    rekey(&(*p).into(), &EncryptionContext(from_session.to_string()), &EncryptionContext(to_session.to_string()), &EncryptionSecret(encryption_secret.to_string())).into()
}
