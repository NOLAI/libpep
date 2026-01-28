//! Commitment types bundling public commitments with their proofs.

#[cfg(feature = "verifiable")]
use crate::core::proved::{
    PseudonymizationFactorCommitments, PseudonymizationFactorCommitmentsProof,
    RekeyFactorCommitments, RekeyFactorCommitmentsProof,
};

/// Pseudonymization factor commitments bundled with their proofs.
///
/// This struct contains both the reshuffle and rekey commitments along with
/// their correctness proofs. It's used for verifiable pseudonymization operations.
#[cfg(feature = "verifiable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProvedPseudonymizationCommitments {
    /// Public commitments for the reshuffle factor
    pub reshuffle_commitments: PseudonymizationFactorCommitments,
    /// Proof that reshuffle commitments are correct
    pub reshuffle_proof: PseudonymizationFactorCommitmentsProof,
    /// Public commitments for the rekey factor
    pub rekey_commitments: RekeyFactorCommitments,
    /// Proof that rekey commitments are correct
    pub rekey_proof: RekeyFactorCommitmentsProof,
}

/// Reshuffle factor commitments bundled with their proof.
///
/// This struct contains the reshuffle commitments along with their correctness proof.
/// It's used for verifiable reshuffling operations (user-specific, per domain).
#[cfg(feature = "verifiable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProvedReshuffleCommitments {
    /// Public commitments for the reshuffle factor
    pub commitments: PseudonymizationFactorCommitments,
    /// Proof that commitments are correct
    pub proof: PseudonymizationFactorCommitmentsProof,
}

/// Rekey factor commitments bundled with their proof.
///
/// This struct contains the rekey commitments along with their correctness proof.
/// It's used for verifiable rekey operations on both pseudonyms and attributes
/// (session-specific, per encryption context).
#[cfg(feature = "verifiable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProvedRekeyCommitments {
    /// Public commitments for the rekey factor
    pub commitments: RekeyFactorCommitments,
    /// Proof that commitments are correct
    pub proof: RekeyFactorCommitmentsProof,
}
