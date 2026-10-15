//! WASM bindings for verifiable transcryptor operations.

use crate::contexts::{WASMEncryptionContext, WASMPseudonymizationDomain};
#[cfg(feature = "long")]
use crate::data::long::{
    WASMLongAttributeRekeyProof, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym,
    WASMLongPseudonymPseudonymizationProof, WASMLongPseudonymRekeyProof,
};
use crate::data::simple::{
    WASMAttributeRekeyProof, WASMEncryptedAttribute, WASMEncryptedPseudonym,
    WASMPseudonymPseudonymizationProof, WASMPseudonymRekeyProof,
};
use crate::factors::commitments::{
    WASMVerifiablePseudonymizationCommitment, WASMVerifiableRekeyCommitment,
    WASMVerifiableTranscryptionCommitment,
};
use crate::factors::types::{WASMAttributeRekeyInfo, WASMPseudonymizationInfo};
use crate::transcryptor::types::WASMTranscryptor;
use libpep::data::verifiable::traits::{VerifiablePseudonymizable, VerifiableRekeyable};
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_class = Transcryptor)]
impl WASMTranscryptor {
    /// Generate the public commitments (combined per transition) for a
    /// pseudonymization transition.
    #[wasm_bindgen(js_name = pseudonymizationCommitment)]
    pub fn pseudonymization_commitment(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiablePseudonymizationCommitment {
        WASMVerifiablePseudonymizationCommitment::from(self.0.pseudonymization_commitment(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    /// Generate the public commitment for an attribute rekey transition.
    #[wasm_bindgen(js_name = attributeRekeyCommitment)]
    pub fn attribute_rekey_commitment(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableRekeyCommitment {
        WASMVerifiableRekeyCommitment::from(
            self.0
                .attribute_rekey_commitment(&session_from.0, &session_to.0),
        )
    }

    /// Generate the public commitment for a pseudonym rekey transition.
    #[wasm_bindgen(js_name = pseudonymRekeyCommitment)]
    pub fn pseudonym_rekey_commitment(
        &self,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableRekeyCommitment {
        WASMVerifiableRekeyCommitment::from(
            self.0
                .pseudonym_rekey_commitment(&session_from.0, &session_to.0),
        )
    }

    /// Perform verifiable pseudonymization and return the operation proof.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> WASMPseudonymPseudonymizationProof {
        encrypted
            .0
            .verifiable_pseudonymize(&pseudo_info.0, &mut rand::rng())
            .into()
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiablePseudonymize)]
    pub fn verifiable_pseudonymize(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::types::WASMPseudonymSessionPublicKey,
    ) -> WASMPseudonymPseudonymizationProof {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        encrypted
            .0
            .verifiable_pseudonymize(&pseudo_info.0, &pk, &mut rand::rng())
            .into()
    }

    /// Perform verifiable attribute rekey and return the operation proof.
    #[wasm_bindgen(js_name = verifiableAttributeRekey)]
    pub fn verifiable_attribute_rekey(
        &self,
        encrypted: &WASMEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> WASMAttributeRekeyProof {
        encrypted
            .0
            .verifiable_rekey(&rekey_info.0, &mut rand::rng())
            .into()
    }

    /// Perform verifiable pseudonym rekey and return the operation proof.
    #[wasm_bindgen(js_name = verifiablePseudonymRekey)]
    pub fn verifiable_pseudonym_rekey(
        &self,
        encrypted: &WASMEncryptedPseudonym,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMPseudonymRekeyProof {
        let info = self.0.pseudonym_rekey_info(&session_from.0, &session_to.0);
        encrypted.0.verifiable_rekey(&info, &mut rand::rng()).into()
    }

    /// Verifiable pseudonymization of a long pseudonym: one batch proof over its blocks.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiableLongPseudonymize)]
    pub fn verifiable_long_pseudonymize(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
    ) -> WASMLongPseudonymPseudonymizationProof {
        encrypted
            .0
            .verifiable_pseudonymize(&pseudo_info.0, &mut rand::rng())
            .into()
    }

    /// Verifiable pseudonymization of a long pseudonym: one batch proof over its blocks.
    /// `public_key` is the key the value is encrypted under.
    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = verifiableLongPseudonymize)]
    pub fn verifiable_long_pseudonymize(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        pseudo_info: &WASMPseudonymizationInfo,
        public_key: &crate::keys::types::WASMPseudonymSessionPublicKey,
    ) -> WASMLongPseudonymPseudonymizationProof {
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        encrypted
            .0
            .verifiable_pseudonymize(&pseudo_info.0, &pk, &mut rand::rng())
            .into()
    }

    /// Verifiable rekeying of a long attribute: one proof per block.
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = verifiableLongAttributeRekey)]
    pub fn verifiable_long_attribute_rekey(
        &self,
        encrypted: &WASMLongEncryptedAttribute,
        rekey_info: &WASMAttributeRekeyInfo,
    ) -> WASMLongAttributeRekeyProof {
        encrypted
            .0
            .verifiable_rekey(&rekey_info.0, &mut rand::rng())
            .into()
    }

    /// Verifiable rekeying of a long pseudonym: one proof per block.
    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = verifiableLongPseudonymRekey)]
    pub fn verifiable_long_pseudonym_rekey(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMLongPseudonymRekeyProof {
        let info = self.0.pseudonym_rekey_info(&session_from.0, &session_to.0);
        encrypted.0.verifiable_rekey(&info, &mut rand::rng()).into()
    }

    /// Build the combined public commitments for a transcryption transition
    /// (pseudonymization + attribute rekey). Used by the verifier to check
    /// `verifiableRecordTranscrypt` proofs.
    #[wasm_bindgen(js_name = transcryptionCommitment)]
    pub fn transcryption_commitment(
        &self,
        domain_from: &WASMPseudonymizationDomain,
        domain_to: &WASMPseudonymizationDomain,
        session_from: &WASMEncryptionContext,
        session_to: &WASMEncryptionContext,
    ) -> WASMVerifiableTranscryptionCommitment {
        WASMVerifiableTranscryptionCommitment::from(self.0.transcryption_commitment(
            &domain_from.0,
            &domain_to.0,
            &session_from.0,
            &session_to.0,
        ))
    }

    /// Perform verifiable transcryption of a simple record.
    ///
    /// Returns a `WASMRecordTranscryptionProof` containing per-item proofs that
    /// the verifier can check against the commitments published for this
    /// transition.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiableRecordTranscrypt)]
    pub fn verifiable_record_transcrypt(
        &self,
        encrypted: &crate::data::records::WASMEncryptedRecord,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
    ) -> crate::data::records::WASMRecordTranscryptionProof {
        let enc: libpep::data::records::EncryptedRecord = encrypted.clone().into();
        let mut rng = rand::rng();
        let proof = self
            .0
            .verifiable_transcrypt(&enc, &transcryption_info.0, &mut rng);
        crate::data::records::WASMRecordTranscryptionProof::from(proof)
    }

    /// Non-elgamal3 variant: the recipient session keys the record was
    /// encrypted under must be supplied so the inner rerandomize step's
    /// binding can be proven.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiableRecordTranscrypt)]
    pub fn verifiable_record_transcrypt(
        &self,
        encrypted: &crate::data::records::WASMEncryptedRecord,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> crate::data::records::WASMRecordTranscryptionProof {
        let enc: libpep::data::records::EncryptedRecord = encrypted.clone().into();
        let sk: libpep::keys::SessionKeys = (*session_keys).into();
        let mut rng = rand::rng();
        let proof =
            self.0
                .verifiable_transcrypt(&enc, &transcryption_info.0, &sk.public(), &mut rng);
        crate::data::records::WASMRecordTranscryptionProof::from(proof)
    }

    /// Perform verifiable transcryption of a long record.
    ///
    /// Returns a `WASMLongRecordTranscryptionProof` containing per-item proofs
    /// that the verifier can check against the commitments published for this
    /// transition.
    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiableLongRecordTranscrypt)]
    pub fn verifiable_long_record_transcrypt(
        &self,
        encrypted: &crate::data::records::WASMLongEncryptedRecord,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
    ) -> crate::data::records::WASMLongRecordTranscryptionProof {
        let enc: libpep::data::records::LongEncryptedRecord = encrypted.clone().into();
        let mut rng = rand::rng();
        let proof = self
            .0
            .verifiable_transcrypt(&enc, &transcryption_info.0, &mut rng);
        crate::data::records::WASMLongRecordTranscryptionProof::from(proof)
    }

    /// Non-elgamal3 variant: the recipient session keys the record was
    /// encrypted under must be supplied so the inner rerandomize step's
    /// binding can be proven.
    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = verifiableLongRecordTranscrypt)]
    pub fn verifiable_long_record_transcrypt(
        &self,
        encrypted: &crate::data::records::WASMLongEncryptedRecord,
        transcryption_info: &crate::factors::types::WASMTranscryptionInfo,
        session_keys: &crate::keys::types::WASMSessionKeys,
    ) -> crate::data::records::WASMLongRecordTranscryptionProof {
        let enc: libpep::data::records::LongEncryptedRecord = encrypted.clone().into();
        let sk: libpep::keys::SessionKeys = (*session_keys).into();
        let mut rng = rand::rng();
        let proof =
            self.0
                .verifiable_transcrypt(&enc, &transcryption_info.0, &sk.public(), &mut rng);
        crate::data::records::WASMLongRecordTranscryptionProof::from(proof)
    }
}
