//! Commitment bundles generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::verifiable::generic::{
    PseudonymizationFactorCommitment, RekeyFactorCommitment,
};

/// The commitments to the reshuffle and rekey factors of a pseudonymization transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct VerifiablePseudonymizationCommitment<G: Group> {
    /// Public commitment to the reshuffle factor: `S = s·G`.
    pub reshuffle_commitment: PseudonymizationFactorCommitment<G>,
    /// Public commitment to the rekey factor: `K = k·G`.
    pub rekey_commitment: RekeyFactorCommitment<G>,
}

/// The commitment to the rekey factor of a rekey transition, of pseudonyms or of attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct VerifiableRekeyCommitment<G: Group> {
    /// Public commitment to the rekey factor: `K = k·G`.
    pub commitment: RekeyFactorCommitment<G>,
}

/// The commitments of a transcryption transition: the pseudonymization commitments for the
/// pseudonyms and the rekey commitment for the attributes, for composite values (records,
/// JSON) that hold both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct VerifiableTranscryptionCommitment<G: Group> {
    /// Pseudonymization commitments (`S = s·G`, `K_pseudo = k·G`).
    pub pseudonym: VerifiablePseudonymizationCommitment<G>,
    /// Attribute rekey commitment (`K_attr = k·G`).
    pub attribute: VerifiableRekeyCommitment<G>,
}
