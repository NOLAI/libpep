//! The distributed transcryptor generic over the [`Group`].

use crate::contexts::EncryptionContext;
use crate::elgamal::arithmetic::group::Group;
use crate::factors::derivation::generic::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor,
};
use crate::factors::{EncryptionSecret, PseudonymizationSecret};
use crate::keys::distribution::blinding::generic::BlindingFactor;
use crate::keys::distribution::shares::generic::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_shares,
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
use crate::transcryptor::types::generic::Transcryptor;

/// A distributed PEP transcryptor system that extends [`Transcryptor<G>`] with blinding factor support
/// for generating session key shares in a distributed transcryptor setup.
///
/// All methods from [`Transcryptor<G>`] are directly accessible via `Deref`.
#[derive(Clone)]
pub struct DistributedTranscryptor<G: Group> {
    pub(crate) system: Transcryptor<G>,
    pub(crate) blinding_factor: BlindingFactor<G>,
}

impl<G: Group> std::ops::Deref for DistributedTranscryptor<G> {
    type Target = Transcryptor<G>;

    fn deref(&self) -> &Self::Target {
        &self.system
    }
}

impl<G: Group> DistributedTranscryptor<G> {
    /// Create a new distributed PEP system with the given secrets and blinding factor.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: BlindingFactor<G>,
    ) -> Self {
        Self {
            system: Transcryptor::new(pseudonymisation_secret, rekeying_secret),
            blinding_factor,
        }
    }

    /// Get a reference to the underlying PEP system.
    pub fn system(&self) -> &Transcryptor<G> {
        &self.system
    }

    /// Get a reference to the blinding factor.
    #[allow(dead_code)]
    /// The blinding factor of this transcryptor.
    ///
    /// Exposes secret material; intended for bindings and embedding code that
    /// manages the transcryptor's configuration.
    pub fn blinding_factor(&self) -> &BlindingFactor<G> {
        &self.blinding_factor
    }

    /// Generate a pseudonym session key share for the given session.
    pub fn pseudonym_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> PseudonymSessionKeyShare<G> {
        let k = make_pseudonym_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_pseudonym_session_key_share(&k, &self.blinding_factor)
    }

    /// Generate an attribute session key share for the given session.
    pub fn attribute_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> AttributeSessionKeyShare<G> {
        let k = make_attribute_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_attribute_session_key_share(&k, &self.blinding_factor)
    }

    /// Generate both pseudonym and attribute session key shares for the given session.
    /// This is a convenience method that returns both shares together.
    pub fn session_key_shares(&self, session: &EncryptionContext) -> SessionKeyShares<G> {
        let pseudonym_rekey_factor =
            make_pseudonym_rekey_factor::<G>(self.system.rekeying_secret(), session);
        let attribute_rekey_factor =
            make_attribute_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_session_key_shares(
            &pseudonym_rekey_factor,
            &attribute_rekey_factor,
            &self.blinding_factor,
        )
    }
}
