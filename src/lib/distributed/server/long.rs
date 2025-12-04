//! Long (multi-block) data type operations for distributed PEP systems and clients.

#[cfg(feature = "batch")]
use crate::core::long::batch::*;
use crate::core::long::data::*;
use crate::core::long::transcryption::*;
#[cfg(feature = "offline")]
use crate::core::transcryption::contexts::*;
use crate::distributed::server::transcryptor::PEPSystem;
use rand_core::{CryptoRng, RngCore};

impl PEPSystem {
    /// Rekey a long encrypted attribute from one session to another, using [`AttributeRekeyInfo`].
    pub fn rekey_long(
        &self,
        encrypted: &LongEncryptedAttribute,
        rekey_info: &AttributeRekeyInfo,
    ) -> LongEncryptedAttribute {
        rekey_long_attribute(encrypted, rekey_info)
    }

    /// Pseudonymize a long encrypted pseudonym from one pseudonymization domain and session to
    /// another, using [`PseudonymizationInfo`].
    pub fn pseudonymize_long(
        &self,
        encrypted: &LongEncryptedPseudonym,
        pseudonymization_info: &PseudonymizationInfo,
    ) -> LongEncryptedPseudonym {
        pseudonymize_long(encrypted, pseudonymization_info)
    }

    /// Rekey a batch of long encrypted attributes from one session to another, using [`AttributeRekeyInfo`].
    /// The order of the attributes is randomly shuffled to avoid linking them.
    #[cfg(feature = "batch")]
    pub fn rekey_long_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [LongEncryptedAttribute],
        rekey_info: &AttributeRekeyInfo,
        rng: &mut R,
    ) -> Box<[LongEncryptedAttribute]> {
        rekey_long_attribute_batch(encrypted, rekey_info, rng)
    }

    /// Pseudonymize a batch of long encrypted pseudonyms from one pseudonymization domain and
    /// session to another, using [`PseudonymizationInfo`].
    /// The order of the pseudonyms is randomly shuffled to avoid linking them.
    #[cfg(feature = "batch")]
    pub fn pseudonymize_long_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [LongEncryptedPseudonym],
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Box<[LongEncryptedPseudonym]> {
        pseudonymize_long_batch(encrypted, pseudonymization_info, rng)
    }

    /// Transcrypt a batch of long encrypted data (pseudonyms and attributes) from one
    /// pseudonymization domain and session to another, using [`TranscryptionInfo`].
    /// The order of the pairs (entities) is randomly shuffled to avoid linking them, but the internal
    /// order of pseudonyms and attributes for the same entity is preserved.
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data do not all have the same structure.
    #[cfg(feature = "batch")]
    pub fn transcrypt_long_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: Vec<LongEncryptedData>,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Result<Vec<LongEncryptedData>, String> {
        transcrypt_long_batch(encrypted, transcryption_info, rng)
    }
}
