//! Distributed transcryptor for generating session key shares.
//!
//! The distributed transcryptor is generic over the [`Ciphersuite`].

use crate::contexts::EncryptionContext;
use crate::elgamal::arithmetic::Ciphersuite;
use crate::factors::derivation::{make_attribute_rekey_factor, make_pseudonym_rekey_factor};
use crate::factors::{EncryptionSecret, PseudonymizationSecret};
use crate::keys::distribution::blinding::BlindingFactor;
#[cfg(feature = "verifiable")]
use crate::keys::distribution::proofs::SessionKeyShareProof;
use crate::keys::distribution::shares::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_shares,
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
#[cfg(feature = "verifiable")]
use crate::keys::distribution::shares::{
    make_attribute_session_key_share_with_proof, make_pseudonym_session_key_share_with_proof,
    make_session_key_shares_with_proof, SessionKeyShareError, SessionKeyShareProofs,
};
use crate::transcryptor::types::Transcryptor;
#[cfg(feature = "verifiable")]
use rand_core::{CryptoRng, Rng};

/// A [`Transcryptor`] in a distributed setup: it additionally holds the blinding factor with
/// which it contributes session key shares.
///
/// All methods of [`Transcryptor`] are available through `Deref`.
#[derive(Clone)]
pub struct DistributedTranscryptor<C: Ciphersuite> {
    pub(crate) system: Transcryptor<C>,
    pub(crate) blinding_factor: BlindingFactor<C::Group>,
}

impl<C: Ciphersuite> std::ops::Deref for DistributedTranscryptor<C> {
    type Target = Transcryptor<C>;

    fn deref(&self) -> &Self::Target {
        &self.system
    }
}

impl<C: Ciphersuite> DistributedTranscryptor<C> {
    /// A distributed transcryptor with the given secrets and blinding factor.
    pub fn new(
        pseudonymization_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: BlindingFactor<C::Group>,
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
    pub fn blinding_factor(&self) -> &BlindingFactor<C::Group> {
        &self.blinding_factor
    }

    /// The pseudonym session key share of this transcryptor for a session.
    pub fn pseudonym_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> PseudonymSessionKeyShare<C::Group> {
        let k = make_pseudonym_rekey_factor::<C>(self.system.rekeying_secret(), session);
        make_pseudonym_session_key_share(&k, &self.blinding_factor)
    }

    /// The attribute session key share of this transcryptor for a session.
    pub fn attribute_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> AttributeSessionKeyShare<C::Group> {
        let k = make_attribute_rekey_factor::<C>(self.system.rekeying_secret(), session);
        make_attribute_session_key_share(&k, &self.blinding_factor)
    }

    /// Both session key shares of this transcryptor for a session.
    pub fn session_key_shares(&self, session: &EncryptionContext) -> SessionKeyShares<C::Group> {
        let pseudonym_rekey_factor =
            make_pseudonym_rekey_factor::<C>(self.system.rekeying_secret(), session);
        let attribute_rekey_factor =
            make_attribute_rekey_factor::<C>(self.system.rekeying_secret(), session);
        make_session_key_shares(
            &pseudonym_rekey_factor,
            &attribute_rekey_factor,
            &self.blinding_factor,
        )
    }

    /// The pseudonym session key share for a session with the proof of its construction, for the
    /// user to check with [`SessionKeyShareProof::verify_share`].
    #[cfg(feature = "verifiable")]
    #[allow(clippy::type_complexity)]
    pub fn pseudonym_session_key_share_with_proof<R: Rng + CryptoRng>(
        &self,
        session: &EncryptionContext,
        rng: &mut R,
    ) -> Result<
        (
            PseudonymSessionKeyShare<C::Group>,
            SessionKeyShareProof<C::Group>,
        ),
        SessionKeyShareError,
    > {
        let k = make_pseudonym_rekey_factor::<C>(self.system.rekeying_secret(), session);
        make_pseudonym_session_key_share_with_proof::<C, R>(&k, &self.blinding_factor, rng)
    }

    /// The attribute session key share for a session with the proof of its construction.
    #[cfg(feature = "verifiable")]
    #[allow(clippy::type_complexity)]
    pub fn attribute_session_key_share_with_proof<R: Rng + CryptoRng>(
        &self,
        session: &EncryptionContext,
        rng: &mut R,
    ) -> Result<
        (
            AttributeSessionKeyShare<C::Group>,
            SessionKeyShareProof<C::Group>,
        ),
        SessionKeyShareError,
    > {
        let k = make_attribute_rekey_factor::<C>(self.system.rekeying_secret(), session);
        make_attribute_session_key_share_with_proof::<C, R>(&k, &self.blinding_factor, rng)
    }

    /// Both session key shares for a session with the proofs of their construction.
    #[cfg(feature = "verifiable")]
    #[allow(clippy::type_complexity)]
    pub fn session_key_shares_with_proof<R: Rng + CryptoRng>(
        &self,
        session: &EncryptionContext,
        rng: &mut R,
    ) -> Result<(SessionKeyShares<C::Group>, SessionKeyShareProofs<C::Group>), SessionKeyShareError>
    {
        let pseudonym_rekey_factor =
            make_pseudonym_rekey_factor::<C>(self.system.rekeying_secret(), session);
        let attribute_rekey_factor =
            make_attribute_rekey_factor::<C>(self.system.rekeying_secret(), session);
        make_session_key_shares_with_proof::<C, R>(
            &pseudonym_rekey_factor,
            &attribute_rekey_factor,
            &self.blinding_factor,
            rng,
        )
    }
}
