//! Transcryptor type definitions.

use crate::contexts::*;
#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymRekeyInfo, PseudonymizationInfo,
    PseudonymizationSecret, TranscryptionInfo,
};
use crate::protocol::Context;
use rand_core::{CryptoRng, Rng};

/// A PEP transcryptor system that can pseudonymize and rekey data, based on
/// a pseudonymisation secret and a rekeying secret, within one protocol [`Context`].
#[derive(Clone)]
pub struct Transcryptor {
    pub(crate) pseudonymisation_secret: PseudonymizationSecret,
    pub(crate) rekeying_secret: EncryptionSecret,
    pub(crate) context: Context,
}

impl Transcryptor {
    /// Create a new PEP system with the given secrets, deriving factors within `context`.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        context: Context,
    ) -> Self {
        Self {
            pseudonymisation_secret,
            rekeying_secret,
            context,
        }
    }

    /// The protocol context this transcryptor derives its factors in.
    pub fn context(&self) -> &Context {
        &self.context
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
    ) -> AttributeRekeyInfo {
        AttributeRekeyInfo::new(
            session_from,
            session_to,
            &self.rekeying_secret,
            &self.context,
        )
    }

    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    pub fn pseudonym_rekey_info(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> PseudonymRekeyInfo {
        PseudonymRekeyInfo::new(
            session_from,
            session_to,
            &self.rekeying_secret,
            &self.context,
        )
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
            &self.context,
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
            &self.context,
        )
    }

    /// Rekey (rerandomize and rekey) encrypted data from one session to another.
    /// Works with any rekeyable type (attributes, long attributes, etc.).
    #[cfg(feature = "elgamal3")]
    pub fn rekey<E, R>(&self, encrypted: &E, rekey_info: &E::RekeyInfo, rng: &mut R) -> E
    where
        E: Rekeyable,
        R: Rng + CryptoRng,
    {
        super::functions::rekey(encrypted, rekey_info, rng)
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
        E: Rekeyable,
        R: Rng + CryptoRng,
    {
        super::functions::rekey(encrypted, rekey_info, public_key, rng)
    }

    /// Pseudonymize (rerandomize, reshuffle and rekey) encrypted data from one domain/session to another.
    /// Works with any pseudonymizable type (pseudonyms, long pseudonyms, etc.).
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

    /// Pseudonymize (rerandomize, reshuffle and rekey) encrypted data from one domain/session to another.
    /// Works with any pseudonymizable type (pseudonyms, long pseudonyms, etc.).
    /// `public_key` is the key the ciphertext is currently encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    pub fn pseudonymize<E, R>(
        &self,
        encrypted: &E,
        pseudonymization_info: &PseudonymizationInfo,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E
    where
        E: Pseudonymizable,
        R: Rng + CryptoRng,
    {
        super::functions::pseudonymize(encrypted, pseudonymization_info, public_key, rng)
    }

    /// Transcrypt (rerandomize, then rekey or pseudonymize) encrypted data from one domain/session to another.
    /// Works with any transcryptable type (pseudonyms, attributes, JSON values, records, etc.).
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

    /// Transcrypt (rerandomize, then rekey or pseudonymize) encrypted data from one domain/session to another.
    /// Works with any transcryptable type (pseudonyms, attributes, JSON values, records, etc.).
    /// `public_key` is the key the ciphertext is currently encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    pub fn transcrypt<E, R>(
        &self,
        encrypted: &E,
        transcryption_info: &TranscryptionInfo,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E
    where
        E: Transcryptable,
        R: Rng + CryptoRng,
    {
        super::functions::transcrypt(encrypted, transcryption_info, public_key, rng)
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
        E: Rekeyable + crate::data::traits::HasStructure + Clone,
        E::RekeyInfo: Copy,
        R: Rng + CryptoRng,
    {
        super::batch::rekey_batch(encrypted, rekey_info, rng)
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
        E: Rekeyable + crate::data::traits::HasStructure + Clone,
        E::RekeyInfo: Copy,
        R: Rng + CryptoRng,
    {
        super::batch::rekey_batch(encrypted, rekey_info, public_key, rng)
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
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Pseudonymizable + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        super::batch::pseudonymize_batch(encrypted, pseudonymization_info, rng)
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
        pseudonymization_info: &PseudonymizationInfo,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Pseudonymizable + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        super::batch::pseudonymize_batch(encrypted, pseudonymization_info, public_key, rng)
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
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Transcryptable + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        super::batch::transcrypt_batch(encrypted, transcryption_info, rng)
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
        transcryption_info: &TranscryptionInfo,
        public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Result<Box<[E]>, crate::errors::BatchError>
    where
        E: Transcryptable + crate::data::traits::HasStructure + Clone,
        R: Rng + CryptoRng,
    {
        super::batch::transcrypt_batch(encrypted, transcryption_info, public_key, rng)
    }
}
