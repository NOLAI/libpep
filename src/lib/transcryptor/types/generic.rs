//! The transcryptor generic over the [`Group`].

use crate::contexts::*;
#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::Group;
use crate::factors::types::generic::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::factors::{EncryptionSecret, PseudonymizationSecret};
use rand_core::{CryptoRng, Rng};
use std::marker::PhantomData;

/// A PEP transcryptor system that can pseudonymize and rekey data, based on
/// a pseudonymisation secret and a rekeying secret.
#[derive(Clone)]
pub struct Transcryptor<G: Group> {
    pub(crate) pseudonymisation_secret: PseudonymizationSecret,
    pub(crate) rekeying_secret: EncryptionSecret,
    pub(crate) group: PhantomData<G>,
}

impl<G: Group> Transcryptor<G> {
    /// Create a new PEP system with the given secrets.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
    ) -> Self {
        Self {
            pseudonymisation_secret,
            rekeying_secret,
            group: PhantomData,
        }
    }

    /// Get a reference to the pseudonymisation secret.
    #[allow(dead_code)]
    /// The pseudonymization secret this transcryptor is configured with.
    ///
    /// Exposes secret material; intended for bindings and embedding code that
    /// manages the transcryptor's configuration.
    pub fn pseudonymisation_secret(&self) -> &PseudonymizationSecret {
        &self.pseudonymisation_secret
    }

    /// Get a reference to the rekeying secret.
    #[allow(dead_code)]
    /// The rekeying (encryption) secret this transcryptor is configured with.
    ///
    /// Exposes secret material; intended for bindings and embedding code that
    /// manages the transcryptor's configuration.
    pub fn rekeying_secret(&self) -> &EncryptionSecret {
        &self.rekeying_secret
    }

    /// Generate an attribute rekey info to rekey attributes from a given [`EncryptionContext`] to another.
    pub fn attribute_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> AttributeRekeyInfo<G> {
        AttributeRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }

    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    pub fn pseudonym_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymRekeyInfo<G> {
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
    ) -> PseudonymizationInfo<G> {
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
    ) -> TranscryptionInfo<G> {
        TranscryptionInfo::new(
            domain_from,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }

    /// Rekey (rerandomize and rekey) encrypted data from one session to another.
    /// Works with any rekeyable type (attributes, long attributes, etc.).
    #[cfg(feature = "elgamal3")]
    pub fn rekey<E, R>(&self, encrypted: &E, rekey_info: &E::RekeyInfo, rng: &mut R) -> E
    where
        E: Rekeyable<Group = G>,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::functions::rekey(encrypted, rekey_info, rng)
    }

    /// Rekey (rerandomize and rekey) encrypted data from one session to another.
    /// Works with any rekeyable type (attributes, long attributes, etc.).
    /// `public_key` is the key the ciphertext is currently encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    pub fn rekey<E, R>(
        &self,
        encrypted: &E,
        rekey_info: &E::RekeyInfo,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E
    where
        E: Rekeyable<Group = G>,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::functions::rekey(encrypted, rekey_info, public_key, rng)
    }

    /// Pseudonymize (rerandomize, reshuffle and rekey) encrypted data from one domain/session to another.
    /// Works with any pseudonymizable type (pseudonyms, long pseudonyms, etc.).
    #[cfg(feature = "elgamal3")]
    pub fn pseudonymize<E, R>(
        &self,
        encrypted: &E,
        pseudonymization_info: &PseudonymizationInfo<G>,
        rng: &mut R,
    ) -> E
    where
        E: Pseudonymizable<Group = G>,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::functions::pseudonymize(encrypted, pseudonymization_info, rng)
    }

    /// Pseudonymize (rerandomize, reshuffle and rekey) encrypted data from one domain/session to another.
    /// Works with any pseudonymizable type (pseudonyms, long pseudonyms, etc.).
    /// `public_key` is the key the ciphertext is currently encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    pub fn pseudonymize<E, R>(
        &self,
        encrypted: &E,
        pseudonymization_info: &PseudonymizationInfo<G>,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E
    where
        E: Pseudonymizable<Group = G>,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::functions::pseudonymize(
            encrypted,
            pseudonymization_info,
            public_key,
            rng,
        )
    }

    /// Transcrypt (rerandomize, then rekey or pseudonymize) encrypted data from one domain/session to another.
    /// Works with any transcryptable type (pseudonyms, attributes, JSON values, records, etc.).
    #[cfg(feature = "elgamal3")]
    pub fn transcrypt<E, R>(
        &self,
        encrypted: &E,
        transcryption_info: &TranscryptionInfo<G>,
        rng: &mut R,
    ) -> E
    where
        E: Transcryptable<Group = G>,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::functions::transcrypt(encrypted, transcryption_info, rng)
    }

    /// Transcrypt (rerandomize, then rekey or pseudonymize) encrypted data from one domain/session to another.
    /// Works with any transcryptable type (pseudonyms, attributes, JSON values, records, etc.).
    /// `public_key` is the key the ciphertext is currently encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    pub fn transcrypt<E, R>(
        &self,
        encrypted: &E,
        transcryption_info: &TranscryptionInfo<G>,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E
    where
        E: Transcryptable<Group = G>,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::functions::transcrypt(encrypted, transcryption_info, public_key, rng)
    }

    /// Rekey a batch of encrypted data from one session to another.
    ///
    /// The batch is shuffled before transcryption so that outputs cannot be linked to inputs by position.
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    pub fn rekey_batch<E, R>(
        &self,
        encrypted: &mut [E],
        rekey_info: &E::RekeyInfo,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Rekeyable<Group = G> + crate::data::traits::HasStructure + Clone,
        E::RekeyInfo: Copy,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::batch::rekey_batch(encrypted, rekey_info, rng)
    }

    /// Rekey a batch of encrypted data from one session to another.
    /// `public_key` is the key the ciphertexts are currently encrypted under.
    ///
    /// The batch is shuffled before transcryption so that outputs cannot be linked to inputs by position.
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    pub fn rekey_batch<E, R>(
        &self,
        encrypted: &mut [E],
        rekey_info: &E::RekeyInfo,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Rekeyable<Group = G> + crate::data::traits::HasStructure + Clone,
        E::RekeyInfo: Copy,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::batch::rekey_batch(encrypted, rekey_info, public_key, rng)
    }

    /// Pseudonymize a batch of encrypted data from one domain/session to another.
    ///
    /// The batch is shuffled before transcryption so that outputs cannot be linked to inputs by position.
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    pub fn pseudonymize_batch<E, R>(
        &self,
        encrypted: &mut [E],
        pseudonymization_info: &PseudonymizationInfo<G>,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Pseudonymizable<Group = G> + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::batch::pseudonymize_batch(encrypted, pseudonymization_info, rng)
    }

    /// Pseudonymize a batch of encrypted data from one domain/session to another.
    /// `public_key` is the key the ciphertexts are currently encrypted under.
    ///
    /// The batch is shuffled before transcryption so that outputs cannot be linked to inputs by position.
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    pub fn pseudonymize_batch<E, R>(
        &self,
        encrypted: &mut [E],
        pseudonymization_info: &PseudonymizationInfo<G>,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Pseudonymizable<Group = G> + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::batch::pseudonymize_batch(
            encrypted,
            pseudonymization_info,
            public_key,
            rng,
        )
    }

    /// Transcrypt a batch of encrypted data from one domain/session to another.
    ///
    /// The batch is shuffled before transcryption so that outputs cannot be linked to inputs by position.
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    pub fn transcrypt_batch<E, R>(
        &self,
        encrypted: &mut [E],
        transcryption_info: &TranscryptionInfo<G>,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Transcryptable<Group = G> + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::batch::transcrypt_batch(encrypted, transcryption_info, rng)
    }

    /// Transcrypt a batch of encrypted data from one domain/session to another.
    /// `public_key` is the key the ciphertexts are currently encrypted under.
    ///
    /// The batch is shuffled before transcryption so that outputs cannot be linked to inputs by position.
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    pub fn transcrypt_batch<E, R>(
        &self,
        encrypted: &mut [E],
        transcryption_info: &TranscryptionInfo<G>,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Transcryptable<Group = G> + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::batch::transcrypt_batch(encrypted, transcryption_info, public_key, rng)
    }
}
