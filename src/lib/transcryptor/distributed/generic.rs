//! The distributed transcryptor generic over the [`Group`].

use crate::contexts::EncryptionContext;
use crate::elgamal::arithmetic::group::Group;
use crate::factors::derivation::generic::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor,
};
use crate::factors::{EncryptionSecret, PseudonymizationSecret};
use crate::keys::distribution::blinding::generic::BlindingFactor;
#[cfg(feature = "verifiable")]
use crate::keys::distribution::proofs::generic::SessionKeyShareProof;
use crate::keys::distribution::shares::generic::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_shares,
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
#[cfg(feature = "verifiable")]
use crate::keys::distribution::shares::generic::{
    make_attribute_session_key_share_with_proof, make_pseudonym_session_key_share_with_proof,
    make_session_key_shares_with_proof, SessionKeyShareError, SessionKeyShareProofs,
};
use crate::transcryptor::types::generic::Transcryptor;
#[cfg(feature = "verifiable")]
use rand_core::{CryptoRng, Rng};

/// A [`Transcryptor`] in a distributed setup: it additionally holds the blinding factor with
/// which it contributes session key shares.
///
/// All methods of [`Transcryptor`] are available through `Deref`.
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
    /// A distributed transcryptor with the given secrets and blinding factor.
    pub fn new(
        pseudonymization_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: BlindingFactor<G>,
    ) -> Self {
        Self {
            system: Transcryptor::new(pseudonymization_secret, rekeying_secret),
            blinding_factor,
        }
    }

    /// The blinding factor of this transcryptor.
    ///
    /// Exposes secret material; intended for bindings and embedding code that manages the
    /// transcryptor's configuration.
    pub fn blinding_factor(&self) -> &BlindingFactor<G> {
        &self.blinding_factor
    }

    /// The pseudonym session key share of this transcryptor for a session.
    pub fn pseudonym_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> PseudonymSessionKeyShare<G> {
        let k = make_pseudonym_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_pseudonym_session_key_share(&k, &self.blinding_factor)
    }

    /// The attribute session key share of this transcryptor for a session.
    pub fn attribute_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> AttributeSessionKeyShare<G> {
        let k = make_attribute_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_attribute_session_key_share(&k, &self.blinding_factor)
    }

    /// Both session key shares of this transcryptor for a session.
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

    /// The pseudonym session key share for a session with the proof of its construction, for the
    /// user to check with [`SessionKeyShareProof::verify_share`].
    #[cfg(feature = "verifiable")]
    pub fn pseudonym_session_key_share_with_proof<R: Rng + CryptoRng>(
        &self,
        session: &EncryptionContext,
        rng: &mut R,
    ) -> Result<(PseudonymSessionKeyShare<G>, SessionKeyShareProof<G>), SessionKeyShareError> {
        let k = make_pseudonym_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_pseudonym_session_key_share_with_proof(&k, &self.blinding_factor, rng)
    }

    /// The attribute session key share for a session with the proof of its construction.
    #[cfg(feature = "verifiable")]
    pub fn attribute_session_key_share_with_proof<R: Rng + CryptoRng>(
        &self,
        session: &EncryptionContext,
        rng: &mut R,
    ) -> Result<(AttributeSessionKeyShare<G>, SessionKeyShareProof<G>), SessionKeyShareError> {
        let k = make_attribute_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_attribute_session_key_share_with_proof(&k, &self.blinding_factor, rng)
    }

    /// Both session key shares for a session with the proofs of their construction.
    #[cfg(feature = "verifiable")]
    pub fn session_key_shares_with_proof<R: Rng + CryptoRng>(
        &self,
        session: &EncryptionContext,
        rng: &mut R,
    ) -> Result<(SessionKeyShares<G>, SessionKeyShareProofs<G>), SessionKeyShareError> {
        let pseudonym_rekey_factor =
            make_pseudonym_rekey_factor::<G>(self.system.rekeying_secret(), session);
        let attribute_rekey_factor =
            make_attribute_rekey_factor::<G>(self.system.rekeying_secret(), session);
        make_session_key_shares_with_proof(
            &pseudonym_rekey_factor,
            &attribute_rekey_factor,
            &self.blinding_factor,
            rng,
        )
    }
}
