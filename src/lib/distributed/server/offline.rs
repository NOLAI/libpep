//! Offline-specific methods for [`PEPSystem`].

use super::core::PEPSystem;
use crate::core::transcryption::contexts::{
    AttributeRekeyInfo, EncryptionContext, PseudonymRekeyInfo, PseudonymizationDomain,
    PseudonymizationInfo, TranscryptionInfo,
};

impl PEPSystem {
    /// Generate an attribute rekey info to rekey attributes from a given [`EncryptionContext`] to another.
    ///
    /// In offline mode, both `session_from` and `session_to` can be `None` to support global encryption.
    pub fn attribute_rekey_info_offline(
        &self,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> AttributeRekeyInfo {
        AttributeRekeyInfo::new(session_from, session_to, self.rekeying_secret())
    }

    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    ///
    /// In offline mode, both `session_from` and `session_to` can be `None` to support global encryption.
    pub fn pseudonym_rekey_info_offline(
        &self,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> PseudonymRekeyInfo {
        PseudonymRekeyInfo::new(session_from, session_to, self.rekeying_secret())
    }

    /// Generate a pseudonymization info to pseudonymize from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    ///
    /// In offline mode, both `session_from` and `session_to` can be `None` to support global encryption.
    pub fn pseudonymization_info_offline(
        &self,
        domain_form: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> PseudonymizationInfo {
        PseudonymizationInfo::new(
            domain_form,
            domain_to,
            session_from,
            session_to,
            self.pseudonymisation_secret(),
            self.rekeying_secret(),
        )
    }

    /// Generate transcryption info to transcrypt from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    ///
    /// In offline mode, both `session_from` and `session_to` can be `None` to support global encryption.
    pub fn transcryption_info_offline(
        &self,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> TranscryptionInfo {
        TranscryptionInfo::new(
            domain_from,
            domain_to,
            session_from,
            session_to,
            self.pseudonymisation_secret(),
            self.rekeying_secret(),
        )
    }
}
