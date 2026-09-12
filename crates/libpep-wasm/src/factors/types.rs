//! WASM bindings for factor types and the transcryption info types that bundle them.

use crate::contexts::{WASMEncryptionContext, WASMPseudonymizationDomain};
use crate::elgamal::arithmetic::scalars::WASMScalarNonZero;
use crate::factors::secrets::{WASMEncryptionSecret, WASMPseudonymizationSecret};
use derive_more::{Deref, From, Into};
use libpep::factors::types::*;
use wasm_bindgen::prelude::*;

/// A factor used to rerandomize an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = RerandomizeFactor)]
pub struct WASMRerandomizeFactor(pub(crate) RerandomizeFactor);

#[wasm_bindgen(js_class = RerandomizeFactor)]
impl WASMRerandomizeFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(RerandomizeFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0.scalar())
    }
}

/// A factor used to reshuffle an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = ReshuffleFactor)]
pub struct WASMReshuffleFactor(pub(crate) ReshuffleFactor);

#[wasm_bindgen(js_class = ReshuffleFactor)]
impl WASMReshuffleFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(ReshuffleFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0.scalar())
    }
}

/// A factor used to rekey pseudonyms between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymRekeyFactor)]
pub struct WASMPseudonymRekeyFactor(pub(crate) PseudonymRekeyFactor);

#[wasm_bindgen(js_class = PseudonymRekeyFactor)]
impl WASMPseudonymRekeyFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(PseudonymRekeyFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0.scalar())
    }
}

/// A factor used to rekey attributes between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeRekeyFactor)]
pub struct WASMAttributeRekeyFactor(pub(crate) AttributeRekeyFactor);

#[wasm_bindgen(js_class = AttributeRekeyFactor)]
impl WASMAttributeRekeyFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(AttributeRekeyFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0.scalar())
    }
}

/// The information required to pseudonymize from one domain and session to another.
///
/// Bundles a reshuffle factor `s` and a pseudonym rekey factor `k`.
#[derive(Copy, Clone, Debug, From, Into)]
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
        Self(PseudonymizationInfo::new(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
        ))
    }

    /// The reshuffle factor.
    #[wasm_bindgen(getter)]
    pub fn s(&self) -> WASMReshuffleFactor {
        WASMReshuffleFactor(self.0.s)
    }

    /// The pseudonym rekey factor.
    #[wasm_bindgen(getter)]
    pub fn k(&self) -> WASMPseudonymRekeyFactor {
        WASMPseudonymRekeyFactor(self.0.k)
    }

    /// The rekey-only part of this info, for rekeying pseudonyms without reshuffling.
    #[wasm_bindgen(getter, js_name = rekeyInfo)]
    pub fn rekey_info(&self) -> WASMPseudonymRekeyInfo {
        WASMPseudonymRekeyInfo(self.0.into())
    }

    /// The info for the opposite direction.
    #[wasm_bindgen(js_name = reverse)]
    pub fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

/// The information required to rekey pseudonyms from one session to another.
#[derive(Copy, Clone, Debug, From, Into)]
#[wasm_bindgen(js_name = PseudonymRekeyInfo)]
pub struct WASMPseudonymRekeyInfo(pub(crate) PseudonymRekeyInfo);

#[wasm_bindgen(js_class = "PseudonymRekeyInfo")]
impl WASMPseudonymRekeyInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        Self(PseudonymRekeyInfo::new(
            &session_from.0,
            &session_to.0,
            &encryption_secret.0,
        ))
    }

    /// The pseudonym rekey factor.
    #[wasm_bindgen(getter)]
    pub fn k(&self) -> WASMPseudonymRekeyFactor {
        WASMPseudonymRekeyFactor(self.0.k)
    }

    /// The info for the opposite direction.
    #[wasm_bindgen(js_name = reverse)]
    pub fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

/// The information required to rekey attributes from one session to another.
#[derive(Copy, Clone, Debug, From, Into)]
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
        Self(AttributeRekeyInfo::new(
            &session_from.0,
            &session_to.0,
            &encryption_secret.0,
        ))
    }

    /// The attribute rekey factor.
    #[wasm_bindgen(getter)]
    pub fn k(&self) -> WASMAttributeRekeyFactor {
        WASMAttributeRekeyFactor(self.0.k)
    }

    /// The info for the opposite direction.
    #[wasm_bindgen(js_name = reverse)]
    pub fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

/// The information required to transcrypt from one domain and session to another.
///
/// Bundles pseudonymization info for pseudonyms and rekey info for attributes.
#[derive(Copy, Clone, Debug, From, Into)]
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
        Self(TranscryptionInfo::new(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
        ))
    }

    /// The pseudonymization info for pseudonyms.
    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo(self.0.pseudonym)
    }

    /// The rekey info for attributes.
    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeRekeyInfo {
        WASMAttributeRekeyInfo(self.0.attribute)
    }

    /// The info for the opposite direction.
    #[wasm_bindgen(js_name = reverse)]
    pub fn reverse(&self) -> Self {
        Self(self.0.reverse())
    }
}

impl From<&WASMPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &WASMPseudonymizationInfo) -> Self {
        x.0
    }
}

impl From<&WASMPseudonymRekeyInfo> for PseudonymRekeyInfo {
    fn from(x: &WASMPseudonymRekeyInfo) -> Self {
        x.0
    }
}

impl From<&WASMAttributeRekeyInfo> for AttributeRekeyInfo {
    fn from(x: &WASMAttributeRekeyInfo) -> Self {
        x.0
    }
}

impl From<&WASMTranscryptionInfo> for TranscryptionInfo {
    fn from(x: &WASMTranscryptionInfo) -> Self {
        x.0
    }
}
