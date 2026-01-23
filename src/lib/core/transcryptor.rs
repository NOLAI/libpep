//! PEP transcryptor system for pseudonymizing and rekeying encrypted data.

#[cfg(feature = "batch")]
use crate::core::batch::{pseudonymize_batch, rekey_batch, transcrypt_batch};
use crate::core::contexts::*;
use crate::core::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::core::factors::{EncryptionSecret, PseudonymizationSecret};
use crate::core::functions::{pseudonymize, rekey, transcrypt};
use rand_core::{CryptoRng, RngCore};

/// A PEP transcryptor system that can pseudonymize and rekey data, based on
/// a pseudonymisation secret and a rekeying secret.
#[derive(Clone)]
pub struct Transcryptor {
    pub(crate) pseudonymisation_secret: PseudonymizationSecret,
    pub(crate) rekeying_secret: EncryptionSecret,
}

impl Transcryptor {
    /// Create a new PEP system with the given secrets.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
    ) -> Self {
        Self {
            pseudonymisation_secret,
            rekeying_secret,
        }
    }

    /// Get a reference to the pseudonymisation secret.
    #[allow(dead_code)]
    pub(crate) fn pseudonymisation_secret(&self) -> &PseudonymizationSecret {
        &self.pseudonymisation_secret
    }

    /// Get a reference to the rekeying secret.
    #[allow(dead_code)]
    pub(crate) fn rekeying_secret(&self) -> &EncryptionSecret {
        &self.rekeying_secret
    }

    /// Generate an attribute rekey info to rekey attributes from a given [`EncryptionContext`] to another.
    pub fn attribute_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> AttributeRekeyInfo {
        AttributeRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }

    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    pub fn pseudonym_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymRekeyInfo {
        PseudonymRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }

    /// Generate a pseudonymization info to pseudonymize from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    pub fn pseudonymization_info(
        &self,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymizationInfo {
        PseudonymizationInfo::new(
            domain_from,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }

    /// Generate a transcryption info to transcrypt from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
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

    /// Rekey encrypted data from one session to another.
    /// Automatically works with any rekeyable type (attributes, long attributes, etc.)
    pub fn rekey<E>(&self, encrypted: &E, rekey_info: &E::RekeyInfo) -> E
    where
        E: Rekeyable,
    {
        rekey(encrypted, rekey_info)
    }

    /// Pseudonymize encrypted data from one domain/session to another.
    /// Automatically works with any pseudonymizable type (pseudonyms, long pseudonyms, etc.)
    pub fn pseudonymize<E>(&self, encrypted: &E, pseudonymization_info: &PseudonymizationInfo) -> E
    where
        E: Pseudonymizable,
    {
        pseudonymize(encrypted, pseudonymization_info)
    }

    /// Transcrypt (rekey or pseudonymize) encrypted data from one domain/session to another.
    /// Automatically works with any transcryptable type (pseudonyms, attributes, JSON values, records, etc.)
    pub fn transcrypt<E>(&self, encrypted: &E, transcryption_info: &TranscryptionInfo) -> E
    where
        E: Transcryptable,
    {
        transcrypt(encrypted, transcryption_info)
    }

    /// Rekey a batch of encrypted data from one session to another.
    /// Automatically works with any rekeyable type (attributes, long attributes, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(feature = "batch")]
    pub fn rekey_batch<E, R>(
        &self,
        encrypted: &mut [E],
        rekey_info: &E::RekeyInfo,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::core::batch::BatchError>
    where
        E: Rekeyable + crate::core::batch::HasStructure + Clone,
        E::RekeyInfo: Copy,
        R: RngCore + CryptoRng,
    {
        rekey_batch(encrypted, rekey_info, rng)
    }

    /// Pseudonymize a batch of encrypted data from one domain/session to another.
    /// Automatically works with any pseudonymizable type (pseudonyms, long pseudonyms, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(feature = "batch")]
    pub fn pseudonymize_batch<E, R>(
        &self,
        encrypted: &mut [E],
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::core::batch::BatchError>
    where
        E: Pseudonymizable + crate::core::batch::HasStructure + Clone,
        R: RngCore + CryptoRng,
    {
        pseudonymize_batch(encrypted, pseudonymization_info, rng)
    }

    /// Transcrypt a batch of encrypted data from one domain/session to another.
    /// Automatically works with any transcryptable type (records, JSON values, long records, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(feature = "batch")]
    pub fn transcrypt_batch<E, R>(
        &self,
        encrypted: &mut [E],
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::core::batch::BatchError>
    where
        E: Transcryptable + crate::core::batch::HasStructure + Clone,
        R: RngCore + CryptoRng,
    {
        transcrypt_batch(encrypted, transcryption_info, rng)
    }
}

// Distributed transcryptor

/// A distributed PEP transcryptor system that extends [`Transcryptor`] with blinding factor support
/// for generating session key shares in a distributed transcryptor setup.
///
/// All methods from [`Transcryptor`] are directly accessible via `Deref`.
#[derive(Clone)]
pub struct DistributedTranscryptor {
    pub(crate) system: Transcryptor,
    pub(crate) blinding_factor: crate::core::keys::distribution::BlindingFactor,
}

impl std::ops::Deref for DistributedTranscryptor {
    type Target = Transcryptor;

    fn deref(&self) -> &Self::Target {
        &self.system
    }
}

impl DistributedTranscryptor {
    /// Create a new distributed PEP system with the given secrets and blinding factor.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: crate::core::keys::distribution::BlindingFactor,
    ) -> Self {
        Self {
            system: Transcryptor::new(pseudonymisation_secret, rekeying_secret),
            blinding_factor,
        }
    }

    /// Get a reference to the underlying PEP system.
    pub fn system(&self) -> &Transcryptor {
        &self.system
    }

    /// Get a reference to the blinding factor.
    #[allow(dead_code)]
    pub(crate) fn blinding_factor(&self) -> &crate::core::keys::distribution::BlindingFactor {
        &self.blinding_factor
    }

    /// Generate a pseudonym session key share for the given session.
    pub fn pseudonym_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> crate::core::keys::distribution::PseudonymSessionKeyShare {
        let k = crate::core::factors::make_pseudonym_rekey_factor(
            self.system.rekeying_secret(),
            session,
        );
        crate::core::keys::distribution::make_pseudonym_session_key_share(&k, &self.blinding_factor)
    }

    /// Generate an attribute session key share for the given session.
    pub fn attribute_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> crate::core::keys::distribution::AttributeSessionKeyShare {
        let k = crate::core::factors::make_attribute_rekey_factor(
            self.system.rekeying_secret(),
            session,
        );
        crate::core::keys::distribution::make_attribute_session_key_share(&k, &self.blinding_factor)
    }

    /// Generate both pseudonym and attribute session key shares for the given session.
    /// This is a convenience method that returns both shares together.
    pub fn session_key_shares(
        &self,
        session: &EncryptionContext,
    ) -> crate::core::keys::distribution::SessionKeyShares {
        let pseudonym_rekey_factor = crate::core::factors::make_pseudonym_rekey_factor(
            self.system.rekeying_secret(),
            session,
        );
        let attribute_rekey_factor = crate::core::factors::make_attribute_rekey_factor(
            self.system.rekeying_secret(),
            session,
        );
        crate::core::keys::distribution::make_session_key_shares(
            &pseudonym_rekey_factor,
            &attribute_rekey_factor,
            &self.blinding_factor,
        )
    }
}
