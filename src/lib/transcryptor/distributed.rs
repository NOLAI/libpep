//! Distributed transcryptor for generating session key shares.

use crate::factors::contexts::EncryptionContext;
use crate::factors::{EncryptionSecret, PseudonymizationSecret};

/// A distributed PEP transcryptor system that extends [`super::types::Transcryptor`] with blinding factor support
/// for generating session key shares in a distributed transcryptor setup.
///
/// All methods from [`super::types::Transcryptor`] are directly accessible via `Deref`.
#[derive(Clone)]
pub struct DistributedTranscryptor {
    pub(crate) system: super::types::Transcryptor,
    pub(crate) blinding_factor: crate::keys::distribution::BlindingFactor,
}

impl std::ops::Deref for DistributedTranscryptor {
    type Target = super::types::Transcryptor;

    fn deref(&self) -> &Self::Target {
        &self.system
    }
}

impl DistributedTranscryptor {
    /// Create a new distributed PEP system with the given secrets and blinding factor.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: crate::keys::distribution::BlindingFactor,
    ) -> Self {
        Self {
            system: super::types::Transcryptor::new(pseudonymisation_secret, rekeying_secret),
            blinding_factor,
        }
    }

    /// Get a reference to the underlying PEP system.
    pub fn system(&self) -> &super::types::Transcryptor {
        &self.system
    }

    /// Get a reference to the blinding factor.
    #[allow(dead_code)]
    pub(crate) fn blinding_factor(&self) -> &crate::keys::distribution::BlindingFactor {
        &self.blinding_factor
    }

    /// Generate a pseudonym session key share for the given session.
    pub fn pseudonym_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> crate::keys::distribution::PseudonymSessionKeyShare {
        let k = crate::factors::make_pseudonym_rekey_factor(self.system.rekeying_secret(), session);
        crate::keys::distribution::make_pseudonym_session_key_share(&k, &self.blinding_factor)
    }

    /// Generate an attribute session key share for the given session.
    pub fn attribute_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> crate::keys::distribution::AttributeSessionKeyShare {
        let k = crate::factors::make_attribute_rekey_factor(self.system.rekeying_secret(), session);
        crate::keys::distribution::make_attribute_session_key_share(&k, &self.blinding_factor)
    }

    /// Generate both pseudonym and attribute session key shares for the given session.
    /// This is a convenience method that returns both shares together.
    pub fn session_key_shares(
        &self,
        session: &EncryptionContext,
    ) -> crate::keys::distribution::SessionKeyShares {
        let pseudonym_rekey_factor =
            crate::factors::make_pseudonym_rekey_factor(self.system.rekeying_secret(), session);
        let attribute_rekey_factor =
            crate::factors::make_attribute_rekey_factor(self.system.rekeying_secret(), session);
        crate::keys::distribution::make_session_key_shares(
            &pseudonym_rekey_factor,
            &attribute_rekey_factor,
            &self.blinding_factor,
        )
    }
}
