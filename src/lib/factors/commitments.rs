//! Commitment types for verifiable transcryption.
//!
//! With the forward-direction constructions, a "commitment" to a factor is a
//! single group element `A = a·G`; no separate proof of well-formedness is
//! required because every verifiable operation proves a relation against `A`
//! directly.

#[cfg(feature = "verifiable")]
use crate::core::verifiable::{PseudonymizationFactorCommitment, RekeyFactorCommitment};

/// Pseudonymization-factor commitments bundling reshuffle and rekey
/// commitments for a `(domain, context)` pair.
#[cfg(feature = "verifiable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiablePseudonymizationCommitment {
    /// Public commitment to the reshuffle factor: `S = s·G`.
    pub reshuffle_commitment: PseudonymizationFactorCommitment,
    /// Public commitment to the rekey factor: `K = k·G`.
    pub rekey_commitment: RekeyFactorCommitment,
}

/// Rekey-factor commitment for an encryption context (used for both pseudonym
/// rekeying and attribute rekeying).
#[cfg(feature = "verifiable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiableRekeyCommitment {
    /// Public commitment to the rekey factor: `K = k·G`.
    pub commitment: RekeyFactorCommitment,
}

/// Transcryption commitments bundling the pseudonym (RRSK) and attribute
/// (rekey) factor commitments. Used to verify proofs over composite values
/// (records, JSON) that touch both pseudonyms and attributes in one go.
#[cfg(feature = "verifiable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiableTranscryptionCommitment {
    /// Pseudonymization commitments (`S = s·G`, `K_pseudo = k·G`).
    pub pseudonym: VerifiablePseudonymizationCommitment,
    /// Attribute rekey commitment (`K_attr = k·G`).
    pub attribute: VerifiableRekeyCommitment,
}
