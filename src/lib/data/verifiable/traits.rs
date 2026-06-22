//! Verifier-side and prover-side traits for verifiable operations.
//!
//! The data-layer companion to the per-operation-type proof structs in
//! [`crate::core::verifiable`]. Each operation kind (rekey, pseudonymization,
//! transcryption) has its own pair of traits — one for the encrypted type
//! that can generate a proof, and one for the proof type that can verify
//! and reconstruct.

#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::{PseudonymizationInfo, TranscryptionInfo};
use rand_core::{CryptoRng, Rng};

/// A trait for encrypted pseudonyms that support verifiable pseudonymization.
///
/// Like [`Pseudonymizable`], this rerandomizes + reshuffles + rekeys (RRSK)
/// per ciphertext, producing a data-layer proof wrapper around
/// [`VerifiableRRSK`](crate::core::verifiable::VerifiableRRSK).
pub trait VerifiablePseudonymizable: Pseudonymizable + Sized {
    /// The proof type for pseudonymization operations.
    /// Implements [`VerifiablePseudonymizationProof`] with `DataType = Self`.
    type PseudonymizationProof: VerifiablePseudonymizationProof<DataType = Self>;

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
/// This trait extends [`Rekeyable`] to provide zero-knowledge proofs that
/// rekey operations were performed correctly. The proof type
/// ([`RekeyProof`](Self::RekeyProof)) implements [`VerifiableRekeyProof`].
pub trait VerifiableRekeyable: Rekeyable + Sized {
    /// The proof type for rekey operations.
    /// Implements [`VerifiableRekeyProof`] with `DataType = Self`.
    type RekeyProof: VerifiableRekeyProof<DataType = Self>;

    /// Rekey with proof generation.
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
pub trait VerifiableTranscryptable: Transcryptable + Sized {
    /// The proof type for transcryption operations. Implements
    /// [`VerifiableTranscryptionProof`] with `DataType = Self`.
    type TranscryptionProof: VerifiableTranscryptionProof<DataType = Self>;

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

/// Verifier-side trait for proofs of a rekey operation.
///
/// Rekey does not involve a rerandomize step, so no recipient public key
/// is needed for verification. Mirrors the shape of
/// [`VerifiableRekey`](crate::core::verifiable::VerifiableRekey) in the
/// core layer.
pub trait VerifiableRekeyProof {
    /// The data type this proof was generated for (the verifier-side input).
    type DataType;
    /// The data type the proof reconstructs to.
    type Output;

    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool;

    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Self::Output>;

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output;
}

/// Verifier-side trait for proofs of a pseudonymization (RRSK) operation.
///
/// Pseudonymization involves a rerandomize step, so under `elgamal2` the
/// verifier needs the recipient `PseudonymSessionPublicKey` that the
/// proof was generated against. Under `elgamal3` each ciphertext carries
/// its own `gy` and the parameter is dropped.
///
/// Mirrors [`VerifiableRRSK`](crate::core::verifiable::VerifiableRRSK).
pub trait VerifiablePseudonymizationProof {
    type DataType;
    type Output;

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool;

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool;

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output>;

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output>;

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output;
}

/// Verifier-side trait for proofs of a transcryption (composite RRSK +
/// rekey) operation on a record-like value.
///
/// Like pseudonymization, transcryption involves a rerandomize step, so
/// under `elgamal2` the verifier needs the recipient public-key bundle
/// (`SessionKeys`). Under `elgamal3` the parameter is dropped.
pub trait VerifiableTranscryptionProof {
    type DataType;
    type Output;

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool;

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool;

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Self::Output>;

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Self::Output>;

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output;
}
