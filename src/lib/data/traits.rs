//! Core traits for encryption and decryption operations.

use crate::factors::TranscryptionInfo;
use crate::factors::{PseudonymizationInfo, RerandomizeFactor};
use rand_core::{CryptoRng, Rng};

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
        R: Rng + CryptoRng;

    /// Encrypt this value using a global key (offline encryption).
    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: Rng + CryptoRng;
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
        R: Rng + CryptoRng;

    /// Rerandomize this encrypted value, creating a binary unlinkable copy of the same message.
    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng;

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

/// A trait for encrypted pseudonyms that can be pseudonymized (rerandomized,
/// reshuffled, and rekeyed via [`rrsk`](crate::core::primitives::rrsk)).
///
/// Pseudonymization rerandomizes the ciphertext with a fresh randomiser `r`
/// (so the same pseudonym pseudonymized twice produces two unlinkable
/// ciphertexts), changes the pseudonymization domain via the reshuffle
/// factor, and rekeys to the destination encryption context.
///
/// This trait is only implemented by
/// [`EncryptedPseudonym`](super::simple::EncryptedPseudonym) and
/// [`LongEncryptedPseudonym`](super::long::LongEncryptedPseudonym), as
/// attributes cannot be reshuffled (they have no pseudonymization domain).
pub trait Pseudonymizable: Encrypted {
    /// Pseudonymize from one domain and context to another, with a freshly
    /// sampled rerandomize factor.
    #[cfg(feature = "elgamal3")]
    fn pseudonymize<R>(&self, info: &PseudonymizationInfo, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng;

    /// Pseudonymize from one domain and context to another, with a freshly
    /// sampled rerandomize factor. `public_key` is the recipient public key
    /// the ciphertext was encrypted under (needed for the rerandomize step
    /// when the ciphertext does not carry it).
    #[cfg(not(feature = "elgamal3"))]
    fn pseudonymize<R>(
        &self,
        info: &PseudonymizationInfo,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng;
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
/// - For pseudonyms: rerandomize + reshuffle + rekey ([`rrsk`](crate::core::primitives::rrsk))
/// - For attributes: rekey only (no rerandomize, no reshuffle)
/// - For JSON values / records: recursively transcrypts all nested values
pub trait Transcryptable: Encrypted {
    /// Transcrypt this encrypted value from one domain and context to another,
    /// rerandomizing pseudonyms with a freshly sampled factor.
    #[cfg(feature = "elgamal3")]
    fn transcrypt<R>(&self, info: &TranscryptionInfo, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng;

    /// Transcrypt this encrypted value. `public_key` is the recipient public
    /// key the ciphertext was encrypted under (needed for the rerandomize
    /// step on pseudonyms when the ciphertext does not carry it).
    #[cfg(not(feature = "elgamal3"))]
    fn transcrypt<R>(
        &self,
        info: &TranscryptionInfo,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng;
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

// Verifiable operation traits

/// A trait for encrypted pseudonyms that support verifiable pseudonymization.
///
/// Like [`Pseudonymizable`], this rerandomizes + reshuffles + rekeys (RRSK)
/// per ciphertext, producing a self-contained [`VerifiableRRSK`](crate::core::verifiable::VerifiableRRSK)
/// proof. The forward-direction proof is verified against the combined
/// `(S, K)` commitments published for the transition (plus the recipient
/// public key `Y` it was encrypted under).
#[cfg(feature = "verifiable")]
pub trait VerifiablePseudonymizable: Pseudonymizable {
    /// The proof type for pseudonymization operations.
    /// - Simple types use a single [`VerifiableRRSK`](crate::core::verifiable::VerifiableRRSK).
    /// - Long types use `Vec<VerifiableRRSK>` (one per block).
    type PseudonymizationProof;

    /// Pseudonymize with proof generation, in elgamal3 mode (the recipient
    /// public key `Y` is carried by the ciphertext).
    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize<R>(
        &self,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Self::PseudonymizationProof
    where
        R: Rng + CryptoRng;

    /// Pseudonymize with proof generation. `public_key` is the recipient
    /// public key the ciphertext was encrypted under, used by the rerandomize
    /// step and as the base for the `pi_y_r` proof inside `VerifiableRRSK`.
    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_pseudonymize<R>(
        &self,
        info: &PseudonymizationInfo,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self::PseudonymizationProof
    where
        R: Rng + CryptoRng;
}

/// A trait for encrypted types that support verifiable rekeying.
///
/// This trait extends [`Rekeyable`] to provide zero-knowledge proofs
/// that rekey operations were performed correctly.
///
/// The proof contains the result, which can be extracted via `.result(original)`.
#[cfg(feature = "verifiable")]
pub trait VerifiableRekeyable: Rekeyable {
    /// The proof type for rekey operations.
    /// - Simple types use a single proof
    /// - Long types use `Vec` of proofs
    type RekeyProof;

    /// Rekey with proof generation.
    ///
    /// Returns an operation proof which contains the result.
    /// The result can be extracted from the proof via `.result(original)`.
    fn verifiable_rekey<R: Rng + CryptoRng>(
        &self,
        info: &Self::RekeyInfo,
        rng: &mut R,
    ) -> Self::RekeyProof;
}

/// A trait for encrypted types that support verifiable transcryption.
///
/// Combines verifiable pseudonymization (RRSK, with rerandomization) for
/// pseudonyms and verifiable rekeying for attributes. Composite types
/// (records, JSON) bundle the per-element proofs in a structure that
/// matches the input.
#[cfg(feature = "verifiable")]
pub trait VerifiableTranscryptable: Transcryptable {
    /// The proof type for transcryption operations.
    /// Structure depends on the complexity of the data type.
    type TranscryptionProof;

    /// Transcrypt with proof generation, in elgamal3 mode.
    #[cfg(feature = "elgamal3")]
    fn verifiable_transcrypt<R>(
        &self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Self::TranscryptionProof
    where
        R: Rng + CryptoRng;

    /// Transcrypt with proof generation. `public_key` is the recipient
    /// public key the ciphertext was encrypted under (needed by the
    /// rerandomize step on pseudonyms).
    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_transcrypt<R>(
        &self,
        info: &TranscryptionInfo,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self::TranscryptionProof
    where
        R: Rng + CryptoRng;
}

#[cfg(feature = "batch")]
pub trait BatchEncryptable: Encryptable + Clone {
    fn preprocess_batch(
        items: &[Self],
    ) -> Result<Vec<Self>, crate::transcryptor::batch::BatchError>;
}
