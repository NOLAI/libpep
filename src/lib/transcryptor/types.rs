//! Transcryptor type definitions.
//!
//! The transcryptor is generic over the [`Ciphersuite`].

use crate::contexts::*;
#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::Ciphersuite;
use crate::factors::types::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::factors::{EncryptionSecret, PseudonymizationSecret};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::KeyProvider;
use rand_core::{CryptoRng, Rng};
use std::marker::PhantomData;

pub use crate::contexts::TranscryptorId;

/// A PEP transcryptor system that can pseudonymize and rekey data, based on
/// a pseudonymization secret and a rekeying secret.
#[derive(Clone)]
pub struct Transcryptor<C: Ciphersuite> {
    pub(crate) pseudonymization_secret: PseudonymizationSecret,
    pub(crate) rekeying_secret: EncryptionSecret,
    pub(crate) group: PhantomData<C::Group>,
}

impl<C: Ciphersuite> Transcryptor<C> {
    /// Create a new PEP system with the given secrets.
    pub fn new(
        pseudonymization_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
    ) -> Self {
        Self {
            pseudonymization_secret,
            rekeying_secret,
            group: PhantomData,
        }
    }

    /// The pseudonymization secret this transcryptor is configured with.
    ///
    /// Exposes secret material; intended for bindings and embedding code that
    /// manages the transcryptor's configuration.
    pub fn pseudonymization_secret(&self) -> &PseudonymizationSecret {
        &self.pseudonymization_secret
    }

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
    ) -> AttributeRekeyInfo<C::Group> {
        AttributeRekeyInfo::new::<C>(session_from, session_to, &self.rekeying_secret)
    }

    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    pub fn pseudonym_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymRekeyInfo<C::Group> {
        PseudonymRekeyInfo::new::<C>(session_from, session_to, &self.rekeying_secret)
    }

    /// Generate a pseudonymization info to pseudonymize from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    pub fn pseudonymization_info(
        &self,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymizationInfo<C::Group> {
        PseudonymizationInfo::new::<C>(
            domain_from,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymization_secret,
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
    ) -> TranscryptionInfo<C::Group> {
        TranscryptionInfo::new::<C>(
            domain_from,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymization_secret,
            &self.rekeying_secret,
        )
    }

    /// Rekey (rerandomize and rekey) encrypted data from one session to another.
    /// Works with any rekeyable type (attributes, long attributes, etc.).
    #[cfg(feature = "elgamal3")]
    pub fn rekey<E, R>(&self, encrypted: &E, rekey_info: &E::RekeyInfo, rng: &mut R) -> E
    where
        E: Rekeyable<Group = C::Group>,
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
        public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
        rng: &mut R,
    ) -> E
    where
        E: Rekeyable<Group = C::Group>,
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
        pseudonymization_info: &PseudonymizationInfo<C::Group>,
        rng: &mut R,
    ) -> E
    where
        E: Pseudonymizable<Group = C::Group>,
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
        pseudonymization_info: &PseudonymizationInfo<C::Group>,
        public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
        rng: &mut R,
    ) -> E
    where
        E: Pseudonymizable<Group = C::Group>,
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
        transcryption_info: &TranscryptionInfo<C::Group>,
        rng: &mut R,
    ) -> E
    where
        E: Transcryptable<Group = C::Group>,
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
        transcryption_info: &TranscryptionInfo<C::Group>,
        public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
        rng: &mut R,
    ) -> E
    where
        E: Transcryptable<Group = C::Group>,
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
        encrypted: &[E],
        rekey_info: &E::RekeyInfo,
        rng: &mut R,
    ) -> Result<Vec<E>, crate::data::batch::BatchError>
    where
        E: Rekeyable<Group = C::Group> + crate::data::traits::HasStructure,
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
        encrypted: &[E],
        rekey_info: &E::RekeyInfo,
        public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
        rng: &mut R,
    ) -> Result<Vec<E>, crate::data::batch::BatchError>
    where
        E: Rekeyable<Group = C::Group> + crate::data::traits::HasStructure,
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
        encrypted: &[E],
        pseudonymization_info: &PseudonymizationInfo<C::Group>,
        rng: &mut R,
    ) -> Result<Vec<E>, crate::data::batch::BatchError>
    where
        E: Pseudonymizable<Group = C::Group> + crate::data::traits::HasStructure,
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
        encrypted: &[E],
        pseudonymization_info: &PseudonymizationInfo<C::Group>,
        public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
        rng: &mut R,
    ) -> Result<Vec<E>, crate::data::batch::BatchError>
    where
        E: Pseudonymizable<Group = C::Group> + crate::data::traits::HasStructure,
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
        encrypted: &[E],
        transcryption_info: &TranscryptionInfo<C::Group>,
        rng: &mut R,
    ) -> Result<Vec<E>, crate::data::batch::BatchError>
    where
        E: Transcryptable<Group = C::Group> + crate::data::traits::HasStructure,
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
        encrypted: &[E],
        transcryption_info: &TranscryptionInfo<C::Group>,
        public_key: &impl KeyProvider<<E::UnencryptedType as Encryptable>::PublicKeyType>,
        rng: &mut R,
    ) -> Result<Vec<E>, crate::data::batch::BatchError>
    where
        E: Transcryptable<Group = C::Group> + crate::data::traits::HasStructure,
        R: Rng + CryptoRng,
    {
        crate::transcryptor::batch::transcrypt_batch(encrypted, transcryption_info, public_key, rng)
    }
}
