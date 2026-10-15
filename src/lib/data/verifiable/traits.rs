//! Verifier-side and prover-side traits for verifiable operations.
//!
//! The data-layer companion to the per-operation-type proof structs in
//! [`crate::elgamal::verifiable`]. Each operation kind (rekey, pseudonymization,
//! transcryption) has its own pair of traits — one for the encrypted type
//! that can generate a proof, and one for the proof type that can verify
//! and reconstruct.

#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
use crate::elgamal::arithmetic::group::Group;
use crate::factors::commitments::generic::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
use crate::factors::types::generic::{PseudonymizationInfo, TranscryptionInfo};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::generic::{PseudonymSessionPublicKey, SessionPublicKeys};
use rand_core::{CryptoRng, Rng};

/// A trait for encrypted pseudonyms that support verifiable pseudonymization.
///
/// Like [`Pseudonymizable`], this rerandomizes + reshuffles + rekeys (RRSK)
/// per ciphertext, producing a data-layer proof wrapper around
/// [`VerifiableRRSK`](crate::elgamal::verifiable::VerifiableRRSK).
pub trait VerifiablePseudonymizable: Pseudonymizable + Sized {
    /// The proof type for pseudonymization operations.
    /// Implements [`VerifiablePseudonymizationProof`] with `DataType = Self`.
    type PseudonymizationProof: VerifiablePseudonymizationProof<
        Group = Self::Group,
        DataType = Self,
    >;

    /// Pseudonymize with proof generation, in elgamal3 mode (the recipient
    /// public key `Y` is carried by the ciphertext).
    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize<R>(
        &self,
        info: &PseudonymizationInfo<Self::Group>,
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
        info: &PseudonymizationInfo<Self::Group>,
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
///
/// This is the paper's VRK (Definition 10): the ciphertext is rekeyed and not rerandomized, so
/// its second component `C` is unchanged, unlike the non-verifiable
/// [`rekey`](crate::data::traits::Rekeyable::rekey), which rerandomizes first. A party that
/// sees input and output can therefore match them by `C`. The paper accepts this because the
/// verifier of a proof always learns that link (Section 3.2.1); choose who verifies
/// accordingly (Section 3.6).
pub trait VerifiableRekeyable: Rekeyable + Sized {
    /// The proof type for rekey operations.
    /// Implements [`VerifiableRekeyProof`] with `DataType = Self`.
    type RekeyProof: VerifiableRekeyProof<Group = Self::Group, DataType = Self>;

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
    type TranscryptionProof: VerifiableTranscryptionProof<Group = Self::Group, DataType = Self>;

    /// Transcrypt with proof generation, in elgamal3 mode.
    #[cfg(feature = "elgamal3")]
    fn verifiable_transcrypt<R>(
        &self,
        info: &TranscryptionInfo<Self::Group>,
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
        info: &TranscryptionInfo<Self::Group>,
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
/// [`VerifiableRekey`](crate::elgamal::verifiable::VerifiableRekey) in the
/// core layer.
pub trait VerifiableRekeyProof {
    /// The group the data is encrypted in.
    type Group: Group;
    /// The data type this proof was generated for (the verifier-side input).
    type DataType;
    /// The data type the proof reconstructs to.
    type Output;

    /// Verify the proof against the original ciphertext and the commitments.
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &VerifiableRekeyCommitment<Self::Group>,
    ) -> bool {
        self.verified_reconstruct(original, commitments).is_some()
    }

    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiableRekeyCommitment<Self::Group>,
    ) -> Option<Self::Output>;

    #[cfg(feature = "insecure")]
    /// The result of the operation, without verifying the proof.
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output;
}

/// Verifier-side trait for proofs of a pseudonymization (RRSK) operation.
///
/// Pseudonymization involves a rerandomize step, so without `elgamal3` the
/// verifier needs the recipient `PseudonymSessionPublicKey` that the
/// proof was generated against. Under `elgamal3` each ciphertext carries
/// its own `gy` and the parameter is dropped.
///
/// Mirrors [`VerifiableRRSK`](crate::elgamal::verifiable::VerifiableRRSK).
pub trait VerifiablePseudonymizationProof {
    /// The group the data is encrypted in.
    type Group: Group;
    /// The encrypted type the proof is about.
    type DataType;
    /// The result of the operation the proof is about.
    type Output;

    #[cfg(feature = "elgamal3")]
    /// Verify the proof against the original ciphertext and the commitments.
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<Self::Group>,
    ) -> bool {
        self.verified_reconstruct(original, commitments).is_some()
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify the proof against the original ciphertext and the commitments; without `elgamal3`,
    /// `public_key` is the key the original was encrypted under.
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<Self::Group>,
        commitments: &VerifiablePseudonymizationCommitment<Self::Group>,
    ) -> bool {
        self.verified_reconstruct(original, public_key, commitments)
            .is_some()
    }

    #[cfg(feature = "elgamal3")]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<Self::Group>,
    ) -> Option<Self::Output>;

    #[cfg(not(feature = "elgamal3"))]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify; without `elgamal3`, `public_key` is the key the original was encrypted under.
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<Self::Group>,
        commitments: &VerifiablePseudonymizationCommitment<Self::Group>,
    ) -> Option<Self::Output>;

    #[cfg(feature = "insecure")]
    /// The result of the operation, without verifying the proof.
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output;
}

/// Verifier-side trait for proofs of a transcryption (composite RRSK +
/// rekey) operation on a record-like value.
///
/// Like pseudonymization, transcryption involves a rerandomize step, so
/// without `elgamal3` the verifier needs the recipient public-key bundle
/// (`SessionPublicKeys`). Under `elgamal3` the parameter is dropped.
pub trait VerifiableTranscryptionProof {
    /// The group the data is encrypted in.
    type Group: Group;
    /// The encrypted type the proof is about.
    type DataType;
    /// The result of the operation the proof is about.
    type Output;

    #[cfg(feature = "elgamal3")]
    /// Verify the proof against the original ciphertext and the commitments.
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &VerifiableTranscryptionCommitment<Self::Group>,
    ) -> bool {
        self.verified_reconstruct(original, commitments).is_some()
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify the proof against the original ciphertext and the commitments; without `elgamal3`,
    /// `public_key` is the key the original was encrypted under.
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &SessionPublicKeys<Self::Group>,
        commitments: &VerifiableTranscryptionCommitment<Self::Group>,
    ) -> bool {
        self.verified_reconstruct(original, public_key, commitments)
            .is_some()
    }

    #[cfg(feature = "elgamal3")]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiableTranscryptionCommitment<Self::Group>,
    ) -> Option<Self::Output>;

    #[cfg(not(feature = "elgamal3"))]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify; without `elgamal3`, `public_key` is the key the original was encrypted under.
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &SessionPublicKeys<Self::Group>,
        commitments: &VerifiableTranscryptionCommitment<Self::Group>,
    ) -> Option<Self::Output>;

    #[cfg(feature = "insecure")]
    /// The result of the operation, without verifying the proof.
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output;
}
