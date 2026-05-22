//! Verifiable transcryptor operations.
//!
//! This module provides methods for the transcryptor to perform verifiable
//! transcryption operations that generate zero-knowledge proofs.

use crate::factors::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo,
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
};
use rand_core::{CryptoRng, RngCore};

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

    /// Perform a verifiable pseudonymization operation.
    ///
    /// Uses RRSK with a freshly sampled rerandomize factor. The result can be
    /// extracted from the proof via `.result()`.
    #[cfg(feature = "elgamal3")]
    pub fn verifiable_pseudonymize<E, R>(
        &self,
        encrypted: &E,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> E::PseudonymizationProof
    where
        E: crate::data::traits::VerifiablePseudonymizable,
        R: RngCore + CryptoRng,
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
        E: crate::data::traits::VerifiablePseudonymizable,
        R: RngCore + CryptoRng,
    {
        encrypted.verifiable_pseudonymize(info, public_key, rng)
    }

    /// Perform a verifiable rekey operation.
    ///
    /// The result can be extracted from the proof via `.result(original)`.
    pub fn verifiable_rekey<E, R>(
        &self,
        encrypted: &E,
        info: &E::RekeyInfo,
        rng: &mut R,
    ) -> E::RekeyProof
    where
        E: crate::data::traits::VerifiableRekeyable,
        R: RngCore + CryptoRng,
    {
        encrypted.verifiable_rekey(info, rng)
    }
}
