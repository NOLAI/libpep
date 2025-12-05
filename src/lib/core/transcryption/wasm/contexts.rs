use super::super::contexts::*;
use super::secrets::{WASMEncryptionSecret, WASMPseudonymizationSecret};
use crate::core::transcryption::contexts::AttributeRekeyFactor;
use derive_more::From;
use wasm_bindgen::prelude::*;

#[derive(Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymizationDomain)]
pub struct WASMPseudonymizationDomain(pub(crate) PseudonymizationDomain);

#[wasm_bindgen(js_class = "PseudonymizationDomain")]
impl WASMPseudonymizationDomain {
    /// Create a specific pseudonymization domain from a string identifier.
    #[wasm_bindgen(constructor)]
    pub fn new(payload: &str) -> Self {
        Self(PseudonymizationDomain::from(payload))
    }

    /// Create a global pseudonymization domain.
    #[cfg(feature = "global-pseudonyms")]
    #[wasm_bindgen]
    pub fn global() -> Self {
        Self(PseudonymizationDomain::global())
    }
}

#[derive(Clone, Debug)]
#[wasm_bindgen(js_name = EncryptionContext)]
pub struct WASMEncryptionContext(pub(crate) EncryptionContext);

#[wasm_bindgen(js_class = "EncryptionContext")]
impl WASMEncryptionContext {
    /// Create a specific encryption context from a string identifier.
    #[wasm_bindgen(constructor)]
    pub fn new(payload: &str) -> Self {
        Self(EncryptionContext::from(payload))
    }

    /// Create a global encryption context.
    #[cfg(feature = "offline")]
    #[wasm_bindgen]
    pub fn global() -> Self {
        Self(EncryptionContext::global())
    }
}

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
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let info = AttributeRekeyInfo::new(&session_from.0, &session_to.0, &encryption_secret.0);
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
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let info = PseudonymizationInfo::new(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
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
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let info = TranscryptionInfo::new(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
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
