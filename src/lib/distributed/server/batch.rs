//! Batch operations for distributed PEP systems.

use crate::core::data::*;
use crate::core::transcryption::batch::*;
use crate::core::transcryption::contexts::*;
use crate::distributed::server::transcryptor::PEPSystem;
use rand_core::{CryptoRng, RngCore};

impl PEPSystem {
    /// Rekey a batch of [`EncryptedAttribute`]s from one session to another, using
    /// [`AttributeRekeyInfo`].
    pub fn rekey_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [EncryptedAttribute],
        rekey_info: &AttributeRekeyInfo,
        rng: &mut R,
    ) -> Box<[EncryptedAttribute]> {
        rekey_batch(encrypted, rekey_info, rng)
    }

    /// Pseudonymize a batch of [`EncryptedPseudonym`]s from one pseudonymization domain and
    /// session to another, using [`PseudonymizationInfo`].
    pub fn pseudonymize_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [EncryptedPseudonym],
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Box<[EncryptedPseudonym]> {
        pseudonymize_batch(encrypted, pseudonymization_info, rng)
    }

    /// Transcrypt a batch of encrypted messages for one entity (see [`EncryptedData`]),
    /// from one pseudonymization domain and session to another, using [`TranscryptionInfo`].
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    pub fn transcrypt_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: Vec<EncryptedData>,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Vec<EncryptedData>, String> {
        transcrypt_batch(encrypted, transcryption_info, rng)
    }
}
