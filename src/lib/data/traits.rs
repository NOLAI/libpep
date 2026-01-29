//! Core traits for encryption and decryption operations.

use crate::factors::TranscryptionInfo;
use crate::factors::{PseudonymizationInfo, RerandomizeFactor};
use rand_core::{CryptoRng, RngCore};

/// A trait for encryptable data types that can be encrypted into [`Encrypted`] types.
///
/// Each type declares its required key types via associated types:
/// - Simple types (Pseudonym, Attribute) use their specific session/global keys
/// - Long types (LongPseudonym, LongAttribute) use the same keys as their block type
/// - Complex types (PEPJSONValue) use key bundles (SessionKeys, GlobalPublicKeys)
///
/// # Examples
///
/// ```rust,ignore
/// // Pseudonym uses PseudonymSessionPublicKey
/// encrypt(&pseudonym, &pseudonym_session_key, rng);
///
/// // LongPseudonym also uses PseudonymSessionPublicKey (encrypts each block)
/// encrypt(&long_pseudonym, &pseudonym_session_key, rng);
///
/// // PEPJSONValue needs SessionKeys (contains both pseudonyms and attributes)
/// encrypt(&json_value, &session_keys, rng);
/// ```
pub trait Encryptable: Sized {
    /// The encrypted version of this type.
    type EncryptedType: Encrypted<UnencryptedType = Self>;

    /// The session public key type required for encryption.
    type PublicKeyType;

    /// The global public key type required for offline encryption.
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType;

    /// Encrypt this value using a session key.
    fn encrypt<R>(&self, public_key: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng;

    /// Encrypt this value using a global key (offline encryption).
    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng;
}

/// A trait for encrypted data types that can be decrypted back into [`Encryptable`] types.
pub trait Encrypted: Sized {
    /// The unencrypted version of this type.
    type UnencryptedType: Encryptable<EncryptedType = Self>;

    /// The session secret key type required for decryption.
    type SecretKeyType;

    /// The global secret key type required for offline decryption.
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType;

    /// Decrypt this value using a session key.
    /// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Option<Self::UnencryptedType>;

    /// Decrypt this value using a session key.
    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Self::UnencryptedType;

    /// Decrypt this value using a global key (offline decryption).
    /// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType>;

    /// Decrypt this value using a global key (offline decryption).
    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType;

    /// Rerandomize this encrypted value, creating a binary unlinkable copy of the same message.
    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng;

    /// Rerandomize this encrypted value, creating a binary unlinkable copy of the same message.
    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng;

    /// Rerandomize this encrypted value using a known rerandomization factor.
    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor) -> Self;

    /// Rerandomize this encrypted value using a known rerandomization factor.
    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor,
    ) -> Self;
}

// Transcryption traits

/// A trait for encrypted pseudonyms that can be pseudonymized (reshuffled + rekeyed).
///
/// Pseudonymization applies both a reshuffle operation (to change the pseudonymization domain)
/// and a rekey operation (to change the encryption context).
///
/// This trait is only implemented by [`EncryptedPseudonym`](super::simple::EncryptedPseudonym) and [`LongEncryptedPseudonym`](super::long::LongEncryptedPseudonym),
/// as attributes cannot be reshuffled (they have no pseudonymization domain).
pub trait Pseudonymizable: Encrypted {
    /// Pseudonymize this encrypted pseudonym from one domain and context to another.
    fn pseudonymize(&self, info: &PseudonymizationInfo) -> Self;
}

/// A trait for encrypted types that can be rekeyed (encryption context change).
///
/// Rekeying changes the encryption context without changing the underlying value.
/// For pseudonyms, this only changes the encryption key (not the domain).
/// For attributes, this is the only transcryption operation available.
pub trait Rekeyable: Encrypted {
    /// The type of rekey information required for this encrypted type.
    type RekeyInfo;

    /// Rekey this encrypted value from one encryption context to another.
    fn rekey(&self, info: &Self::RekeyInfo) -> Self;
}

/// A trait for encrypted types that can be transcrypted.
///
/// Transcryption combines domain change and encryption context change:
/// - For pseudonyms: applies both pseudonymization (reshuffle + rekey)
/// - For attributes: applies only rekeying (no reshuffle possible)
/// - For JSON values: recursively transcrypts all nested values
pub trait Transcryptable: Encrypted {
    /// Transcrypt this encrypted value from one domain and context to another.
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self;
}

/// A trait for encrypted types that have a structure that must be validated during batch operations.
///
/// Types implementing this trait require all items in a batch to have the same structure
/// (e.g., same number of pseudonyms/attributes in records, same JSON shape, etc.).
#[cfg(feature = "batch")]
pub trait HasStructure {
    /// The type representing the structure of this encrypted value.
    type Structure: PartialEq + std::fmt::Debug;

    /// Get the structure of this encrypted value.
    fn structure(&self) -> Self::Structure;
}
