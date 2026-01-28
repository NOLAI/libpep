//! Verifiable transcryptor operations.
//!
//! This module provides methods for the transcryptor to perform verifiable
//! transcryption operations that generate zero-knowledge proofs.

use crate::core::proved::RSKFactorsProof;
use crate::factors::{
    AttributeRekeyInfo, ProvedPseudonymizationCommitments, ProvedRekeyCommitments,
    PseudonymRekeyInfo, PseudonymizationInfo,
};
use rand_core::{CryptoRng, RngCore};

use super::types::Transcryptor;

impl Transcryptor {
    /// Generate commitments for pseudonymization info.
    ///
    /// This creates public commitments to the pseudonymization factors that can be published
    /// and used by verifiers to check that operations are performed correctly.
    ///
    /// # Arguments
    ///
    /// * `info` - The pseudonymization info to create commitments for
    /// * `rng` - Random number generator for creating commitments
    ///
    /// # Returns
    ///
    /// Proved commitments bundling both reshuffle and rekey commitments with their proofs
    pub fn pseudonymization_commitments<R: RngCore + CryptoRng>(
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> ProvedPseudonymizationCommitments {
        use crate::core::proved::{PseudonymizationFactorCommitments, RekeyFactorCommitments};

        let (reshuffle_commitments, reshuffle_proof) =
            PseudonymizationFactorCommitments::new(&info.s.0, rng);
        let (rekey_commitments, rekey_proof) = RekeyFactorCommitments::new(&info.k.0, rng);

        ProvedPseudonymizationCommitments {
            reshuffle_commitments,
            reshuffle_proof,
            rekey_commitments,
            rekey_proof,
        }
    }

    /// Generate commitments for pseudonym rekey info.
    ///
    /// This creates public commitments to the rekey factor that can be published
    /// and used by verifiers to check that rekey operations are performed correctly.
    ///
    /// # Arguments
    ///
    /// * `info` - The pseudonym rekey info to create commitments for
    /// * `rng` - Random number generator for creating commitments
    ///
    /// # Returns
    ///
    /// Proved commitments bundling rekey commitments with their proof
    pub fn pseudonym_rekey_commitments<R: RngCore + CryptoRng>(
        info: &PseudonymRekeyInfo,
        rng: &mut R,
    ) -> ProvedRekeyCommitments {
        use crate::core::proved::RekeyFactorCommitments;

        let (commitments, proof) = RekeyFactorCommitments::new(&info.0, rng);

        ProvedRekeyCommitments { commitments, proof }
    }

    /// Generate commitments for attribute rekey info.
    ///
    /// This creates public commitments to the rekey factor that can be published
    /// and used by verifiers to check that rekey operations are performed correctly.
    ///
    /// # Arguments
    ///
    /// * `info` - The attribute rekey info to create commitments for
    /// * `rng` - Random number generator for creating commitments
    ///
    /// # Returns
    ///
    /// Proved commitments bundling rekey commitments with their proof
    pub fn attribute_rekey_commitments<R: RngCore + CryptoRng>(
        info: &AttributeRekeyInfo,
        rng: &mut R,
    ) -> ProvedRekeyCommitments {
        use crate::core::proved::RekeyFactorCommitments;

        let (commitments, proof) = RekeyFactorCommitments::new(&info.0, rng);

        ProvedRekeyCommitments { commitments, proof }
    }

    /// Perform a verifiable pseudonymization operation.
    ///
    /// This generates a proof that can be verified by third parties using only
    /// the public commitments (not included in this method).
    ///
    /// The result can be extracted from the proof via `.result()`.
    ///
    /// # Returns
    ///
    /// The operation proof (contains the result).
    ///
    /// # Note
    ///
    /// The factors proof (RSKFactorsProof) is not message-specific. Generate it once
    /// per pseudonymization info using `RSKFactorsProof::new(&info.s.0, &info.k.0, rng)`.
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

    /// Generate a factors proof for pseudonymization verification.
    ///
    /// The factors proof is not message-specific and should be generated once
    /// per pseudonymization info, not per message.
    ///
    /// # Arguments
    ///
    /// * `info` - The pseudonymization info to create a factors proof for
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// The RSK factors proof
    pub fn pseudonymization_factors_proof<R: RngCore + CryptoRng>(
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> RSKFactorsProof {
        RSKFactorsProof::new(&info.s.0, &info.k.0, rng)
    }

    /// Perform a verifiable rekey operation.
    ///
    /// This generates a proof that can be verified by third parties using only
    /// the public commitments (not included in this method).
    ///
    /// The result can be extracted from the proof via `.result(original)`.
    ///
    /// # Returns
    ///
    /// The operation proof (contains the result)
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
