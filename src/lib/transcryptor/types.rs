//! Transcryptor type definitions.

use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::contexts::*;
use crate::factors::types::RekeyInfoProvider;
use crate::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymRekeyInfo, PseudonymizationInfo,
    PseudonymizationSecret, TranscryptionInfo,
};
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
        super::functions::rekey(encrypted, rekey_info)
    }

    /// Pseudonymize encrypted data from one domain/session to another.
    /// Automatically works with any pseudonymizable type (pseudonyms, long pseudonyms, etc.)
    pub fn pseudonymize<E>(&self, encrypted: &E, pseudonymization_info: &PseudonymizationInfo) -> E
    where
        E: Pseudonymizable,
    {
        super::functions::pseudonymize(encrypted, pseudonymization_info)
    }

    /// Transcrypt (rekey or pseudonymize) encrypted data from one domain/session to another.
    /// Automatically works with any transcryptable type (pseudonyms, attributes, JSON values, records, etc.)
    pub fn transcrypt<E>(&self, encrypted: &E, transcryption_info: &TranscryptionInfo) -> E
    where
        E: Transcryptable,
    {
        super::functions::transcrypt(encrypted, transcryption_info)
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
    ) -> Result<Box<[E]>, super::batch::BatchError>
    where
        E: Rekeyable + crate::data::traits::HasStructure + Clone,
        E::RekeyInfo: Copy,
        R: RngCore + CryptoRng,
    {
        super::batch::rekey_batch(encrypted, rekey_info, rng)
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
    ) -> Result<Box<[E]>, super::batch::BatchError>
    where
        E: Pseudonymizable + crate::data::traits::HasStructure + Clone,
        R: RngCore + CryptoRng,
    {
        super::batch::pseudonymize_batch(encrypted, pseudonymization_info, rng)
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
    ) -> Result<Box<[E]>, super::batch::BatchError>
    where
        E: Transcryptable + crate::data::traits::HasStructure + Clone,
        R: RngCore + CryptoRng,
    {
        super::batch::transcrypt_batch(encrypted, transcryption_info, rng)
    }
}

impl RekeyInfoProvider<AttributeRekeyInfo> for Transcryptor {
    fn rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> AttributeRekeyInfo {
        self.attribute_rekey_info(session_from, session_to)
    }
}

impl RekeyInfoProvider<PseudonymRekeyInfo> for Transcryptor {
    fn rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymRekeyInfo {
        self.pseudonym_rekey_info(session_from, session_to)
    }
}
