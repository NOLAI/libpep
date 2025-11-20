//! High-level [`PEPSystem`]s and [`PEPClient`]s.

use crate::distributed::key_blinding::*;
use crate::high_level::core::*;
use crate::high_level::transcryption::contexts::*;
use crate::high_level::transcryption::ops::*;
use crate::high_level::transcryption::secrets::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, EncryptionSecret,
    PseudonymizationSecret,
};

/// A PEP transcryptor system that can [pseudonymize] and [rekey] data, based on
/// a pseudonymisation secret, a rekeying secret and a blinding factor.
#[derive(Clone)]
pub struct PEPSystem {
    pseudonymisation_secret: PseudonymizationSecret,
    rekeying_secret: EncryptionSecret,
    blinding_factor: BlindingFactor,
}
impl PEPSystem {
    /// Create a new PEP system with the given secrets and blinding factor.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: BlindingFactor,
    ) -> Self {
        Self {
            pseudonymisation_secret,
            rekeying_secret,
            blinding_factor,
        }
    }
    /// Generate a pseudonym session key share for the given session.
    pub fn pseudonym_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> PseudonymSessionKeyShare {
        let k = make_pseudonym_rekey_factor(&self.rekeying_secret, session);
        make_pseudonym_session_key_share(&k.0, &self.blinding_factor)
    }
    /// Generate an attribute session key share for the given session.
    pub fn attribute_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> AttributeSessionKeyShare {
        let k = make_attribute_rekey_factor(&self.rekeying_secret, session);
        make_attribute_session_key_share(&k.0, &self.blinding_factor)
    }

    /// Generate both pseudonym and attribute session key shares for the given session.
    /// This is a convenience method that returns both shares together.
    pub fn session_key_shares(&self, session: &EncryptionContext) -> SessionKeyShares {
        let pseudonym_rekey_factor = make_pseudonym_rekey_factor(&self.rekeying_secret, session);
        let attribute_rekey_factor = make_attribute_rekey_factor(&self.rekeying_secret, session);
        make_session_key_shares(
            &pseudonym_rekey_factor.0,
            &attribute_rekey_factor.0,
            &self.blinding_factor,
        )
    }
    /// Generate an attribute rekey info to rekey attributes from a given [`EncryptionContext`] to another.
    #[cfg(feature = "global")]
    pub fn attribute_rekey_info(
        &self,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> AttributeRekeyInfo {
        AttributeRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }
    /// Generate an attribute rekey info to rekey attributes from a given [`EncryptionContext`] to another.
    #[cfg(not(feature = "global"))]
    pub fn attribute_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> AttributeRekeyInfo {
        AttributeRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }
    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    #[cfg(feature = "global")]
    pub fn pseudonym_rekey_info(
        &self,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> PseudonymRekeyInfo {
        PseudonymRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }
    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    #[cfg(not(feature = "global"))]
    pub fn pseudonym_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymRekeyInfo {
        PseudonymRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }
    /// Generate a pseudonymization info to pseudonymize from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    #[cfg(feature = "global")]
    pub fn pseudonymization_info(
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
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }
    /// Generate a pseudonymization info to pseudonymize from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    #[cfg(not(feature = "global"))]
    pub fn pseudonymization_info(
        &self,
        domain_form: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymizationInfo {
        PseudonymizationInfo::new(
            domain_form,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }
    /// Rekey an [`EncryptedAttribute`] from one session to another, using [`AttributeRekeyInfo`].
    pub fn rekey(
        &self,
        encrypted: &EncryptedAttribute,
        rekey_info: &AttributeRekeyInfo,
    ) -> EncryptedAttribute {
        rekey(encrypted, rekey_info)
    }
    /// Pseudonymize an [`EncryptedPseudonym`] from one pseudonymization domain and session to
    /// another, using [`PseudonymizationInfo`].
    pub fn pseudonymize(
        &self,
        encrypted: &EncryptedPseudonym,
        pseudonymization_info: &PseudonymizationInfo,
    ) -> EncryptedPseudonym {
        pseudonymize(encrypted, pseudonymization_info)
    }

    /// Generate transcryption info to transcrypt from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    #[cfg(feature = "global")]
    pub fn transcryption_info(
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
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }
    /// Generate transcryption info to transcrypt from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    #[cfg(not(feature = "global"))]
    pub fn transcryption_info(
        &self,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> TranscryptionInfo {
        TranscryptionInfo::new(
            domain_from,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }

    /// Transcrypt (rekey or pseudonymize) an encrypted message from one pseudonymization domain and
    /// session to another, using [`TranscryptionInfo`].
    pub fn transcrypt<E: Transcryptable>(
        &self,
        encrypted: &E,
        transcryption_info: &TranscryptionInfo,
    ) -> E {
        transcrypt(encrypted, transcryption_info)
    }
}
