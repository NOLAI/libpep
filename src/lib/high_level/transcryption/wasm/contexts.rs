use super::super::contexts::*;
use crate::high_level::transcryption::contexts::AttributeRekeyFactor;
use crate::high_level::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};
use derive_more::From;
use wasm_bindgen::prelude::*;

#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymRekeyFactor)]
pub struct WASMPseudonymRekeyFactor(pub(crate) PseudonymRekeyFactor);

#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = AttributeRekeyInfo)]
pub struct WASMAttributeRekeyInfo(pub(crate) AttributeRekeyInfo);

#[wasm_bindgen(js_class = "AttributeRekeyInfo")]
impl WASMAttributeRekeyInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        session_from: Option<String>,
        session_to: Option<String>,
        encryption_secret: Vec<u8>,
    ) -> Self {
        let info = AttributeRekeyInfo::new(
            session_from
                .as_ref()
                .map(|s| EncryptionContext::from(s.as_str()))
                .as_ref(),
            session_to
                .as_ref()
                .map(|s| EncryptionContext::from(s.as_str()))
                .as_ref(),
            &EncryptionSecret::from(encryption_secret),
        );
        WASMAttributeRekeyInfo(info)
    }

    #[wasm_bindgen(js_name = reverse)]
    pub fn reverse(&self) -> WASMAttributeRekeyInfo {
        WASMAttributeRekeyInfo(AttributeRekeyFactor(self.0 .0.invert()))
    }
}

#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymizationInfo)]
pub struct WASMPseudonymizationInfo(pub(crate) PseudonymizationInfo);

#[wasm_bindgen(js_class = "PseudonymizationInfo")]
impl WASMPseudonymizationInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: Option<String>,
        session_to: Option<String>,
        pseudonymization_secret: Vec<u8>,
        encryption_secret: Vec<u8>,
    ) -> Self {
        let info = PseudonymizationInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            session_from
                .as_ref()
                .map(|s| EncryptionContext::from(s.as_str()))
                .as_ref(),
            session_to
                .as_ref()
                .map(|s| EncryptionContext::from(s.as_str()))
                .as_ref(),
            &PseudonymizationSecret::from(pseudonymization_secret),
            &EncryptionSecret::from(encryption_secret),
        );
        WASMPseudonymizationInfo(info)
    }

    #[wasm_bindgen(getter)]
    pub fn k(&self) -> WASMPseudonymRekeyFactor {
        WASMPseudonymRekeyFactor(self.0.k)
    }

    #[wasm_bindgen(js_name = reverse)]
    pub fn reverse(&self) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo(PseudonymizationInfo {
            s: ReshuffleFactor(self.0.s.0.invert()),
            k: PseudonymRekeyFactor(self.0.k.0.invert()),
        })
    }
}

#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = TranscryptionInfo)]
pub struct WASMTranscryptionInfo(pub(crate) TranscryptionInfo);

#[wasm_bindgen(js_class = "TranscryptionInfo")]
impl WASMTranscryptionInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: Option<String>,
        session_to: Option<String>,
        pseudonymization_secret: Vec<u8>,
        encryption_secret: Vec<u8>,
    ) -> Self {
        let info = TranscryptionInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            session_from
                .as_ref()
                .map(|s| EncryptionContext::from(s.as_str()))
                .as_ref(),
            session_to
                .as_ref()
                .map(|s| EncryptionContext::from(s.as_str()))
                .as_ref(),
            &PseudonymizationSecret::from(pseudonymization_secret),
            &EncryptionSecret::from(encryption_secret),
        );
        WASMTranscryptionInfo(info)
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo(self.0.pseudonym)
    }

    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeRekeyInfo {
        WASMAttributeRekeyInfo(self.0.attribute)
    }

    #[wasm_bindgen(js_name = reverse)]
    pub fn reverse(&self) -> WASMTranscryptionInfo {
        WASMTranscryptionInfo(TranscryptionInfo {
            pseudonym: PseudonymizationInfo {
                s: ReshuffleFactor(self.0.pseudonym.s.0.invert()),
                k: PseudonymRekeyFactor(self.0.pseudonym.k.0.invert()),
            },
            attribute: AttributeRekeyFactor(self.0.attribute.0.invert()),
        })
    }
}

impl From<AttributeRekeyInfo> for WASMAttributeRekeyInfo {
    fn from(x: AttributeRekeyInfo) -> Self {
        WASMAttributeRekeyInfo(x)
    }
}

impl From<&WASMAttributeRekeyInfo> for AttributeRekeyInfo {
    fn from(x: &WASMAttributeRekeyInfo) -> Self {
        x.0
    }
}

impl From<&WASMPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &WASMPseudonymizationInfo) -> Self {
        x.0
    }
}

impl From<TranscryptionInfo> for WASMTranscryptionInfo {
    fn from(x: TranscryptionInfo) -> Self {
        WASMTranscryptionInfo(x)
    }
}

impl From<&WASMTranscryptionInfo> for TranscryptionInfo {
    fn from(x: &WASMTranscryptionInfo) -> Self {
        x.0
    }
}
