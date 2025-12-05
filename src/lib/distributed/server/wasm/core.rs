use super::super::transcryptor::PEPSystem;
use super::setup::WASMBlindingFactor;
use crate::core::data::{EncryptedAttribute, EncryptedPseudonym};
#[cfg(feature = "long")]
use crate::core::long::data::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "long")]
use crate::core::long::wasm::data::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
use crate::core::transcryption::contexts::*;
use crate::core::transcryption::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::core::transcryption::wasm::contexts::{
    WASMAttributeRekeyInfo, WASMEncryptionContext, WASMPseudonymRekeyFactor,
    WASMPseudonymizationDomain, WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
use crate::core::wasm::data::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
use crate::distributed::client::wasm::keys::{
    WASMAttributeSessionKeyShare, WASMPseudonymSessionKeyShare, WASMSessionKeyShares,
};
use crate::distributed::server::setup::BlindingFactor;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A PEP transcryptor system.
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

    #[wasm_bindgen(js_name = pseudonymSessionKeyShare)]
    pub fn wasm_pseudonym_session_key_share(
        &self,
        session: &WASMEncryptionContext,
    ) -> WASMPseudonymSessionKeyShare {
        WASMPseudonymSessionKeyShare(self.pseudonym_session_key_share(&session.0))
    }

    #[wasm_bindgen(js_name = attributeSessionKeyShare)]
    pub fn wasm_attribute_session_key_share(
        &self,
        session: &WASMEncryptionContext,
    ) -> WASMAttributeSessionKeyShare {
        WASMAttributeSessionKeyShare(self.attribute_session_key_share(&session.0))
    }

    #[wasm_bindgen(js_name = sessionKeyShares)]
    pub fn wasm_session_key_shares(&self, session: &WASMEncryptionContext) -> WASMSessionKeyShares {
        WASMSessionKeyShares(self.session_key_shares(&session.0))
    }

    #[wasm_bindgen(js_name = attributeRekeyInfo)]
    pub fn wasm_attribute_rekey_info(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMAttributeRekeyInfo {
        WASMAttributeRekeyInfo::from(self.attribute_rekey_info(&session_from.0, &session_to.0))
    }

    #[wasm_bindgen(js_name = pseudonymRekeyInfo)]
    pub fn wasm_pseudonym_rekey_info(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMPseudonymRekeyFactor {
        WASMPseudonymRekeyFactor::from(self.pseudonym_rekey_info(&session_from.0, &session_to.0))
    }

    #[wasm_bindgen(js_name = pseudonymizationInfo)]
    pub fn wasm_pseudonymization_info(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMPseudonymizationInfo {
        WASMPseudonymizationInfo::from(self.pseudonymization_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    #[wasm_bindgen(js_name = transcryptionInfo)]
    pub fn wasm_transcryption_info(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMTranscryptionInfo {
        WASMTranscryptionInfo::from(self.transcryption_info(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    #[wasm_bindgen(js_name = rekey)]
    pub fn wasm_rekey(
        &self,
        encrypted: &WASMEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> WASMEncryptedAttribute {
        WASMEncryptedAttribute::from(
            self.rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)),
        )
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

    #[wasm_bindgen(js_name = rekeyBatch)]
    pub fn wasm_rekey_batch(
        &self,
        encrypted: Vec<WASMEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Vec<WASMEncryptedAttribute> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<EncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self.rekey_batch(
            &mut encrypted,
            &AttributeRekeyInfo::from(rekey_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(WASMEncryptedAttribute::from)
            .collect()
    }

    #[wasm_bindgen(js_name = pseudonymizeBatch)]
    pub fn wasm_pseudonymize_batch(
        &self,
        encrypted: Vec<WASMEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> Vec<WASMEncryptedPseudonym> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<EncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let result = self.pseudonymize_batch(
            &mut encrypted,
            &PseudonymizationInfo::from(pseudonymization_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(WASMEncryptedPseudonym::from)
            .collect()
    }

    // Long data type methods

    /// Rekey a long encrypted attribute from one session to another.
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = rekeyLong)]
    pub fn wasm_rekey_long(
        &self,
        encrypted: &WASMLongEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> WASMLongEncryptedAttribute {
        WASMLongEncryptedAttribute::from(
            self.rekey_long(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)),
        )
    }

    /// Pseudonymize a long encrypted pseudonym from one domain/session to another.
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = pseudonymizeLong)]
    pub fn wasm_pseudonymize_long(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> WASMLongEncryptedPseudonym {
        WASMLongEncryptedPseudonym::from(self.pseudonymize_long(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudonymization_info),
        ))
    }

    /// Rekey a batch of long encrypted attributes from one session to another.
    #[cfg(all(feature = "long", feature = "batch"))]
    #[wasm_bindgen(js_name = rekeyLongBatch)]
    pub fn wasm_rekey_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Vec<WASMLongEncryptedAttribute> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<LongEncryptedAttribute> =
            encrypted.into_iter().map(|e| e.0).collect();
        let result = self.rekey_long_batch(
            &mut encrypted,
            &AttributeRekeyInfo::from(rekey_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(WASMLongEncryptedAttribute::from)
            .collect()
    }

    /// Pseudonymize a batch of long encrypted pseudonyms from one domain/session to another.
    #[cfg(all(feature = "long", feature = "batch"))]
    #[wasm_bindgen(js_name = pseudonymizeLongBatch)]
    pub fn wasm_pseudonymize_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> Vec<WASMLongEncryptedPseudonym> {
        let mut rng = rand::rng();
        let mut encrypted: Vec<LongEncryptedPseudonym> =
            encrypted.into_iter().map(|e| e.0).collect();
        let result = self.pseudonymize_long_batch(
            &mut encrypted,
            &PseudonymizationInfo::from(pseudonymization_info),
            &mut rng,
        );
        result
            .into_vec()
            .into_iter()
            .map(WASMLongEncryptedPseudonym::from)
            .collect()
    }

    /// Transcrypt an EncryptedPEPJSONValue from one context to another.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The EncryptedPEPJSONValue to transcrypt
    /// * `transcryption_info` - The transcryption information
    ///
    /// # Returns
    ///
    /// A transcrypted EncryptedPEPJSONValue
    #[cfg(feature = "json")]
    #[wasm_bindgen(js_name = transcryptJSON)]
    pub fn transcrypt_json(
        &self,
        encrypted: &crate::core::json::wasm::WASMEncryptedPEPJSONValue,
        transcryption_info: &crate::core::transcryption::wasm::contexts::WASMTranscryptionInfo,
    ) -> crate::core::json::wasm::WASMEncryptedPEPJSONValue {
        use std::ops::Deref;
        let transcrypted = self
            .deref()
            .transcrypt_json(&encrypted.0, &transcryption_info.0);
        crate::core::json::wasm::WASMEncryptedPEPJSONValue(transcrypted)
    }

    /// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
    ///
    /// # Arguments
    ///
    /// * `values` - Array of EncryptedPEPJSONValue objects
    /// * `transcryption_info` - The transcryption information
    ///
    /// # Returns
    ///
    /// A shuffled array of transcrypted EncryptedPEPJSONValue objects
    #[cfg(all(feature = "json", feature = "batch"))]
    #[wasm_bindgen(js_name = transcryptJSONBatch)]
    pub fn transcrypt_json_batch(
        &self,
        values: Vec<crate::core::json::wasm::WASMEncryptedPEPJSONValue>,
        transcryption_info: &crate::core::transcryption::wasm::contexts::WASMTranscryptionInfo,
    ) -> Result<Vec<crate::core::json::wasm::WASMEncryptedPEPJSONValue>, wasm_bindgen::JsValue>
    {
        use std::ops::Deref;
        let mut rng = rand::rng();
        let rust_values: Vec<_> = values.into_iter().map(|v| v.0).collect();
        let transcrypted = self
            .deref()
            .transcrypt_json_batch(rust_values, &transcryption_info.0, &mut rng)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&e))?;
        Ok(transcrypted
            .into_iter()
            .map(crate::core::json::wasm::WASMEncryptedPEPJSONValue)
            .collect())
    }
}
