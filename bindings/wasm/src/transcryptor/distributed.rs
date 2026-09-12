//! WASM bindings for distributed transcryptor.

use crate::contexts::{WASMEncryptionContext, WASMPseudonymizationDomain};
#[cfg(feature = "long")]
use crate::data::long::{WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym};
use crate::data::records::WASMEncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::WASMLongEncryptedRecord;
use crate::data::simple::{WASMEncryptedAttribute, WASMEncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::errors::batch_err_to_js;
use crate::factors::types::WASMPseudonymRekeyInfo;
use crate::factors::types::{
    WASMAttributeRekeyInfo, WASMPseudonymizationInfo, WASMTranscryptionInfo,
};
use crate::keys::distribution::WASMBlindingFactor;
use crate::keys::{
    WASMAttributeSessionKeyShare, WASMPseudonymSessionKeyShare, WASMSessionKeyShares,
};
use derive_more::{Deref, From, Into};
#[cfg(all(feature = "long", feature = "batch"))]
use libpep::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "batch")]
use libpep::data::simple::{EncryptedAttribute, EncryptedPseudonym};
use libpep::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymizationInfo, PseudonymizationSecret,
};
use libpep::keys::distribution::BlindingFactor;
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;
use libpep::transcryptor::DistributedTranscryptor;
use wasm_bindgen::prelude::*;

/// A distributed PEP transcryptor system with blinding factor support.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = DistributedTranscryptor)]
pub struct WASMDistributedTranscryptor(pub(crate) DistributedTranscryptor);

#[wasm_bindgen(js_class = DistributedTranscryptor)]
impl WASMDistributedTranscryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonymisation_secret: &str,
        rekeying_secret: &str,
        blinding_factor: &WASMBlindingFactor,
    ) -> Self {
        Self(DistributedTranscryptor::new(
            PseudonymizationSecret::from(pseudonymisation_secret.as_bytes().into()),
            EncryptionSecret::from(rekeying_secret.as_bytes().into()),
            BlindingFactor::from_scalar(*blinding_factor.0.value()),
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
    ) -> WASMPseudonymRekeyInfo {
        WASMPseudonymRekeyInfo::from(self.pseudonym_rekey_info(&session_from.0, &session_to.0))
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

    /// Build the public commitments for a pseudonymization transition.
    #[cfg(feature = "verifiable")]
    #[wasm_bindgen(js_name = pseudonymizationCommitment)]
    pub fn wasm_pseudonymization_commitment(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> crate::factors::commitments::WASMVerifiablePseudonymizationCommitment {
        crate::factors::commitments::WASMVerifiablePseudonymizationCommitment::from(
            self.0.pseudonymization_commitment(
                &domain_from.0,
                &domain_to.0,
                &session_from.0,
                &session_to.0,
            ),
        )
    }

    /// Build the public commitment for an attribute rekey transition.
    #[cfg(feature = "verifiable")]
    #[wasm_bindgen(js_name = attributeRekeyCommitment)]
    pub fn wasm_attribute_rekey_commitment(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> crate::factors::commitments::WASMVerifiableRekeyCommitment {
        crate::factors::commitments::WASMVerifiableRekeyCommitment::from(
            self.0
                .attribute_rekey_commitment(&session_from.0, &session_to.0),
        )
    }

    /// Build the public commitment for a pseudonym rekey transition.
    #[cfg(feature = "verifiable")]
    #[wasm_bindgen(js_name = pseudonymRekeyCommitment)]
    pub fn wasm_pseudonym_rekey_commitment(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> crate::factors::commitments::WASMVerifiableRekeyCommitment {
        crate::factors::commitments::WASMVerifiableRekeyCommitment::from(
            self.0
                .pseudonym_rekey_commitment(&session_from.0, &session_to.0),
        )
    }

    /// Build the combined public commitments for a transcryption transition.
    #[cfg(feature = "verifiable")]
    #[wasm_bindgen(js_name = transcryptionCommitment)]
    pub fn wasm_transcryption_commitment(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> crate::factors::commitments::WASMVerifiableTranscryptionCommitment {
        crate::factors::commitments::WASMVerifiableTranscryptionCommitment::from(
            self.0.transcryption_commitment(
                &domain_from.0,
                &domain_to.0,
                &session_from.0,
                &session_to.0,
            ),
        )
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

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> WASMEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudo_info),
            &mut rng,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = pseudonymize)]
    pub fn wasm_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::types::WASMPseudonymSessionPublicKey,
    ) -> WASMEncryptedPseudonym {
        let mut rng = rand::rng();
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        WASMEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudo_info),
            &pk,
            &mut rng,
        ))
    }

    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = rekeyBatch)]
    pub fn wasm_rekey_batch(
        &self,
        encrypted: Vec<WASMEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Result<Vec<WASMEncryptedAttribute>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<EncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let mut batch = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        batch
            .rekey(&AttributeRekeyInfo::from(rekey_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMEncryptedAttribute::from)
            .collect())
    }

    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = rekeyBatch)]
    pub fn wasm_rekey_batch(
        &self,
        encrypted: Vec<WASMEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
        public_key: &crate::keys::types::WASMAttributeSessionPublicKey,
    ) -> Result<Vec<WASMEncryptedAttribute>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<EncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let pk = libpep::keys::AttributeSessionPublicKey::from_point(public_key.0 .0);
        let mut batch = EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        batch
            .rekey(&AttributeRekeyInfo::from(rekey_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMEncryptedAttribute::from)
            .collect())
    }

    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = pseudonymizeBatch)]
    pub fn wasm_pseudonymize_batch(
        &self,
        encrypted: Vec<WASMEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> Result<Vec<WASMEncryptedPseudonym>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<EncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let mut batch = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        batch
            .pseudonymize(&PseudonymizationInfo::from(pseudonymization_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMEncryptedPseudonym::from)
            .collect())
    }

    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = pseudonymizeBatch)]
    pub fn wasm_pseudonymize_batch(
        &self,
        encrypted: Vec<WASMEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::types::WASMPseudonymSessionPublicKey,
    ) -> Result<Vec<WASMEncryptedPseudonym>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<EncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let mut batch = EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        batch
            .pseudonymize(&PseudonymizationInfo::from(pseudonymization_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMEncryptedPseudonym::from)
            .collect())
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
            self.rekey(&encrypted.0, &AttributeRekeyInfo::from(rekey_info)),
        )
    }

    /// Pseudonymize a long encrypted pseudonym from one domain/session to another.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = pseudonymizeLong)]
    pub fn wasm_pseudonymize_long(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> WASMLongEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMLongEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudonymization_info),
            &mut rng,
        ))
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = pseudonymizeLong)]
    pub fn wasm_pseudonymize_long(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudonymization_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::types::WASMPseudonymSessionPublicKey,
    ) -> WASMLongEncryptedPseudonym {
        let mut rng = rand::rng();
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        WASMLongEncryptedPseudonym::from(self.pseudonymize(
            &encrypted.0,
            &PseudonymizationInfo::from(pseudonymization_info),
            &pk,
            &mut rng,
        ))
    }

    /// Rekey a batch of long encrypted attributes from one session to another.
    #[cfg(all(feature = "long", feature = "batch", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = rekeyLongBatch)]
    pub fn wasm_rekey_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> Result<Vec<WASMLongEncryptedAttribute>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<LongEncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let mut batch = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        batch
            .rekey(&AttributeRekeyInfo::from(rekey_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMLongEncryptedAttribute::from)
            .collect())
    }

    #[cfg(all(feature = "long", feature = "batch", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = rekeyLongBatch)]
    pub fn wasm_rekey_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedAttribute>,
        rekey_info: &WASMAttributeRekeyInfo,
        public_key: &crate::keys::types::WASMAttributeSessionPublicKey,
    ) -> Result<Vec<WASMLongEncryptedAttribute>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<LongEncryptedAttribute> = encrypted.into_iter().map(|e| e.0).collect();
        let pk = libpep::keys::AttributeSessionPublicKey::from_point(public_key.0 .0);
        let mut batch = EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        batch
            .rekey(&AttributeRekeyInfo::from(rekey_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMLongEncryptedAttribute::from)
            .collect())
    }

    /// Pseudonymize a batch of long encrypted pseudonyms from one domain/session to another.
    #[cfg(all(feature = "long", feature = "batch", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = pseudonymizeLongBatch)]
    pub fn wasm_pseudonymize_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
    ) -> Result<Vec<WASMLongEncryptedPseudonym>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<LongEncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let mut batch = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        batch
            .pseudonymize(&PseudonymizationInfo::from(pseudonymization_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMLongEncryptedPseudonym::from)
            .collect())
    }

    #[cfg(all(feature = "long", feature = "batch", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = pseudonymizeLongBatch)]
    pub fn wasm_pseudonymize_long_batch(
        &self,
        encrypted: Vec<WASMLongEncryptedPseudonym>,
        pseudonymization_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::types::WASMPseudonymSessionPublicKey,
    ) -> Result<Vec<WASMLongEncryptedPseudonym>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<LongEncryptedPseudonym> = encrypted.into_iter().map(|e| e.0).collect();
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let mut batch = EncryptedBatch::new(items, pk).map_err(batch_err_to_js)?;
        batch
            .pseudonymize(&PseudonymizationInfo::from(pseudonymization_info), &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMLongEncryptedPseudonym::from)
            .collect())
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
    #[cfg(all(feature = "json", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptJSON)]
    pub fn transcrypt_json(
        &self,
        encrypted: &crate::data::json::WASMEncryptedPEPJSONValue,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
    ) -> crate::data::json::WASMEncryptedPEPJSONValue {
        let mut rng = rand::rng();
        let transcrypted = self.transcrypt(&encrypted.0, &transcryption_info.0, &mut rng);
        crate::data::json::WASMEncryptedPEPJSONValue(transcrypted)
    }

    #[cfg(all(feature = "json", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = transcryptJSON)]
    pub fn transcrypt_json(
        &self,
        encrypted: &crate::data::json::WASMEncryptedPEPJSONValue,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> crate::data::json::WASMEncryptedPEPJSONValue {
        let mut rng = rand::rng();
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        let transcrypted = self.transcrypt(&encrypted.0, &transcryption_info.0, &keys, &mut rng);
        crate::data::json::WASMEncryptedPEPJSONValue(transcrypted)
    }

    /// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
    #[cfg(all(feature = "json", feature = "batch", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptJSONBatch)]
    pub fn transcrypt_json_batch(
        &self,
        values: Vec<crate::data::json::WASMEncryptedPEPJSONValue>,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
    ) -> Result<Vec<crate::data::json::WASMEncryptedPEPJSONValue>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<_> = values.into_iter().map(|v| v.0).collect();
        let mut batch = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        batch
            .transcrypt(&transcryption_info.0, &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(crate::data::json::WASMEncryptedPEPJSONValue)
            .collect())
    }

    #[cfg(all(feature = "json", feature = "batch", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = transcryptJSONBatch)]
    pub fn transcrypt_json_batch(
        &self,
        values: Vec<crate::data::json::WASMEncryptedPEPJSONValue>,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> Result<Vec<crate::data::json::WASMEncryptedPEPJSONValue>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<_> = values.into_iter().map(|v| v.0).collect();
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        let mut batch = EncryptedBatch::new(items, keys).map_err(batch_err_to_js)?;
        batch
            .transcrypt(&transcryption_info.0, &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(crate::data::json::WASMEncryptedPEPJSONValue)
            .collect())
    }

    /// Transcrypt an EncryptedRecord from one context to another.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = transcryptRecord)]
    pub fn transcrypt_record(
        &self,
        encrypted: WASMEncryptedRecord,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> WASMEncryptedRecord {
        use libpep::data::records::EncryptedRecord;
        use libpep::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: EncryptedRecord = encrypted.into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &mut rng);
        transcrypted.into()
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptRecord)]
    pub fn transcrypt_record(
        &self,
        encrypted: WASMEncryptedRecord,
        transcryption_info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> WASMEncryptedRecord {
        use libpep::data::records::EncryptedRecord;
        use libpep::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: EncryptedRecord = encrypted.into();
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &keys, &mut rng);
        transcrypted.into()
    }

    /// Transcrypt a LongEncryptedRecord from one context to another.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptLongRecord)]
    pub fn transcrypt_long_record(
        &self,
        encrypted: WASMLongEncryptedRecord,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> WASMLongEncryptedRecord {
        use libpep::data::records::LongEncryptedRecord;
        use libpep::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: LongEncryptedRecord = encrypted.into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &mut rng);
        transcrypted.into()
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = transcryptLongRecord)]
    pub fn transcrypt_long_record(
        &self,
        encrypted: WASMLongEncryptedRecord,
        transcryption_info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> WASMLongEncryptedRecord {
        use libpep::data::records::LongEncryptedRecord;
        use libpep::data::traits::Transcryptable;
        let mut rng = rand::rng();
        let rust_encrypted: LongEncryptedRecord = encrypted.into();
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        let transcrypted = rust_encrypted.transcrypt(&transcryption_info.0, &keys, &mut rng);
        transcrypted.into()
    }

    /// Transcrypt a batch of EncryptedRecords and shuffle their order.
    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptRecordBatch)]
    pub fn transcrypt_record_batch(
        &self,
        records: Vec<WASMEncryptedRecord>,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> Result<Vec<WASMEncryptedRecord>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<libpep::data::records::EncryptedRecord> =
            records.into_iter().map(|r| r.into()).collect();
        let mut batch = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        batch
            .transcrypt(&transcryption_info.0, &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMEncryptedRecord::from)
            .collect())
    }

    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = transcryptRecordBatch)]
    pub fn transcrypt_record_batch(
        &self,
        records: Vec<WASMEncryptedRecord>,
        transcryption_info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> Result<Vec<WASMEncryptedRecord>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<libpep::data::records::EncryptedRecord> =
            records.into_iter().map(|r| r.into()).collect();
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        let mut batch = EncryptedBatch::new(items, keys).map_err(batch_err_to_js)?;
        batch
            .transcrypt(&transcryption_info.0, &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMEncryptedRecord::from)
            .collect())
    }

    /// Transcrypt a batch of LongEncryptedRecords and shuffle their order.
    #[cfg(all(feature = "long", feature = "batch", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = transcryptLongRecordBatch)]
    pub fn transcrypt_long_record_batch(
        &self,
        records: Vec<WASMLongEncryptedRecord>,
        transcryption_info: &WASMTranscryptionInfo,
    ) -> Result<Vec<WASMLongEncryptedRecord>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<libpep::data::records::LongEncryptedRecord> =
            records.into_iter().map(|r| r.into()).collect();
        let mut batch = EncryptedBatch::new(items).map_err(batch_err_to_js)?;
        batch
            .transcrypt(&transcryption_info.0, &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMLongEncryptedRecord::from)
            .collect())
    }

    #[cfg(all(feature = "long", feature = "batch", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = transcryptLongRecordBatch)]
    pub fn transcrypt_long_record_batch(
        &self,
        records: Vec<WASMLongEncryptedRecord>,
        transcryption_info: &WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> Result<Vec<WASMLongEncryptedRecord>, wasm_bindgen::JsValue> {
        use libpep::data::batch::EncryptedBatch;
        let mut rng = rand::rng();
        let items: Vec<libpep::data::records::LongEncryptedRecord> =
            records.into_iter().map(|r| r.into()).collect();
        let keys: libpep::keys::SessionKeys = (*session_keys).into();
        let mut batch = EncryptedBatch::new(items, keys).map_err(batch_err_to_js)?;
        batch
            .transcrypt(&transcryption_info.0, &mut rng)
            .map_err(batch_err_to_js)?;
        Ok(batch
            .into_items()
            .into_iter()
            .map(WASMLongEncryptedRecord::from)
            .collect())
    }
}
