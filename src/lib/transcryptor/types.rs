//! Transcryptor type definitions.

use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::contexts::*;
use crate::factors::types::RekeyInfoProvider;
use crate::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymRekeyInfo, PseudonymizationInfo,
    PseudonymizationSecret, TranscryptionInfo,
};
use rand_core::{CryptoRng, Rng};

/// Transcryptor identifier for distributed PEP systems.
pub type TranscryptorId = String;

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
    /// Internally uses RRSK with a freshly sampled rerandomize factor.
    #[cfg(feature = "elgamal3")]
    pub fn pseudonymize<E, R>(
        &self,
        encrypted: &E,
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> E
    where
        E: Pseudonymizable,
        R: Rng + CryptoRng,
    {
        super::functions::pseudonymize(encrypted, pseudonymization_info, rng)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn pseudonymize<E, R>(
        &self,
        encrypted: &E,
        pseudonymization_info: &PseudonymizationInfo,
        public_key: &<E::UnencryptedType as crate::data::traits::Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E
    where
        E: Pseudonymizable,
        R: Rng + CryptoRng,
    {
        super::functions::pseudonymize(encrypted, pseudonymization_info, public_key, rng)
    }

    /// Transcrypt encrypted data from one domain/session to another.
    /// Internally pseudonyms use RRSK (rerandomize+reshuffle+rekey) with a
    /// freshly sampled factor, attributes use rekey only.
    #[cfg(feature = "elgamal3")]
    pub fn transcrypt<E, R>(
        &self,
        encrypted: &E,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> E
    where
        E: Transcryptable,
        R: Rng + CryptoRng,
    {
        super::functions::transcrypt(encrypted, transcryption_info, rng)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn transcrypt<E, R>(
        &self,
        encrypted: &E,
        transcryption_info: &TranscryptionInfo,
        public_key: &<E::UnencryptedType as crate::data::traits::Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E
    where
        E: Transcryptable,
        R: Rng + CryptoRng,
    {
        super::functions::transcrypt(encrypted, transcryption_info, public_key, rng)
    }
}

// Batch operations live as methods on `EncryptedBatch<E>` itself (one impl
// per concrete `E`). Call them directly on the batch — there is no
// polymorphic batch wrapper on `Transcryptor` because each batch shape has
// its own concrete signature.

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
