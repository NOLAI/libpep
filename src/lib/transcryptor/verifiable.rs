//! Verifiable transcryptor operations.
//!
//! This module provides methods for the transcryptor to perform verifiable
//! transcryption operations that generate zero-knowledge proofs.

use crate::factors::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
use rand_core::{CryptoRng, Rng};

use super::types::Transcryptor;

impl Transcryptor {
    /// Build the public commitments for a pseudonymization info: forward
    /// commitments `S = s·G` and `K = k·G` to the reshuffle and rekey factors.
    pub fn pseudonymization_commitment(
        info: &PseudonymizationInfo,
    ) -> VerifiablePseudonymizationCommitment {
        use crate::core::verifiable::{PseudonymizationFactorCommitment, RekeyFactorCommitment};
        let reshuffle_commitment = PseudonymizationFactorCommitment::new(&info.s.0);
        let rekey_commitment = RekeyFactorCommitment::new(&info.k.0);
        VerifiablePseudonymizationCommitment {
            reshuffle_commitment,
            rekey_commitment,
        }
    }

    /// Build the public commitment for a pseudonym rekey info: `K = k·G`.
    pub fn pseudonym_rekey_commitment(info: &PseudonymRekeyInfo) -> VerifiableRekeyCommitment {
        use crate::core::verifiable::RekeyFactorCommitment;
        VerifiableRekeyCommitment {
            commitment: RekeyFactorCommitment::new(&info.0),
        }
    }

    /// Build the public commitment for an attribute rekey info: `K = k·G`.
    pub fn attribute_rekey_commitment(info: &AttributeRekeyInfo) -> VerifiableRekeyCommitment {
        use crate::core::verifiable::RekeyFactorCommitment;
        VerifiableRekeyCommitment {
            commitment: RekeyFactorCommitment::new(&info.0),
        }
    }

    /// Build the combined public commitments for a transcryption info:
    /// pseudonymization (`S`, `K_pseudo`) and attribute rekey (`K_attr`).
    pub fn transcryption_commitment(info: &TranscryptionInfo) -> VerifiableTranscryptionCommitment {
        VerifiableTranscryptionCommitment {
            pseudonym: Self::pseudonymization_commitment(&info.pseudonym),
            attribute: Self::attribute_rekey_commitment(&info.attribute),
        }
    }

    /// Perform a verifiable pseudonymization operation.
    ///
    /// Uses RRSK with a freshly sampled rerandomize factor. The verifier
    /// recovers the result by calling
    /// [`Verifier::verify_pseudonymization`](crate::verifier::Verifier::verify_pseudonymization)
    /// (or its `_cached` variant) on the returned proof.
    #[cfg(feature = "elgamal3")]
    pub fn verifiable_pseudonymize<E, R>(
        &self,
        encrypted: &E,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> E::PseudonymizationProof
    where
        E: crate::data::verifiable::traits::VerifiablePseudonymizable,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_pseudonymize(info, rng)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verifiable_pseudonymize<E, R>(
        &self,
        encrypted: &E,
        info: &PseudonymizationInfo,
        public_key: &<E::UnencryptedType as crate::data::traits::Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E::PseudonymizationProof
    where
        E: crate::data::verifiable::traits::VerifiablePseudonymizable,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_pseudonymize(info, public_key, rng)
    }

    /// Perform a verifiable rekey operation.
    ///
    /// The verifier recovers the result by calling
    /// [`Verifier::verify_pseudonym_rekey`](crate::verifier::Verifier::verify_pseudonym_rekey)
    /// or [`Verifier::verify_attribute_rekey`](crate::verifier::Verifier::verify_attribute_rekey)
    /// on the returned proof.
    pub fn verifiable_rekey<E, R>(
        &self,
        encrypted: &E,
        info: &E::RekeyInfo,
        rng: &mut R,
    ) -> E::RekeyProof
    where
        E: crate::data::verifiable::traits::VerifiableRekeyable,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_rekey(info, rng)
    }

    /// Perform a verifiable transcryption operation on composite values
    /// (records, JSON). Pseudonym fields get verifiable RRSK; attribute
    /// fields get verifiable rekey. The returned proof bundles both.
    #[cfg(feature = "elgamal3")]
    pub fn verifiable_transcrypt<E, R>(
        &self,
        encrypted: &E,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> E::TranscryptionProof
    where
        E: crate::data::verifiable::traits::VerifiableTranscryptable,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_transcrypt(info, rng)
    }

    /// Perform a verifiable transcryption operation on composite values
    /// (records, JSON). `public_key` is the recipient public key the
    /// pseudonym ciphertexts were encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    pub fn verifiable_transcrypt<E, R>(
        &self,
        encrypted: &E,
        info: &TranscryptionInfo,
        public_key: &<E::UnencryptedType as crate::data::traits::Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E::TranscryptionProof
    where
        E: crate::data::verifiable::traits::VerifiableTranscryptable,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_transcrypt(info, public_key, rng)
    }
}
