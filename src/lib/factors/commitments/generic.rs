//! Commitment bundles generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::verifiable::generic::{
    PseudonymizationFactorCommitment, RekeyFactorCommitment,
};
use crate::factors::types::generic::{
    AttributeRekeyInfo, Factor, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
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

impl<G: Group> From<PseudonymizationInfo<G>> for VerifiablePseudonymizationCommitment<G> {
    /// The commitments to the factors of `info`.
    fn from(info: PseudonymizationInfo<G>) -> Self {
        Self {
            reshuffle_commitment: PseudonymizationFactorCommitment::new(&info.s.scalar()),
            rekey_commitment: RekeyFactorCommitment::new(&info.k.scalar()),
        }
    }
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

impl<G: Group> From<PseudonymRekeyInfo<G>> for VerifiableRekeyCommitment<G> {
    /// The commitment to the factor of `info`.
    fn from(info: PseudonymRekeyInfo<G>) -> Self {
        Self {
            commitment: RekeyFactorCommitment::new(&info.k.scalar()),
        }
    }
}

impl<G: Group> From<AttributeRekeyInfo<G>> for VerifiableRekeyCommitment<G> {
    /// The commitment to the factor of `info`.
    fn from(info: AttributeRekeyInfo<G>) -> Self {
        Self {
            commitment: RekeyFactorCommitment::new(&info.k.scalar()),
        }
    }
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

impl<G: Group> From<TranscryptionInfo<G>> for VerifiableTranscryptionCommitment<G> {
    /// The commitments to the factors of `info`.
    fn from(info: TranscryptionInfo<G>) -> Self {
        Self {
            pseudonym: info.pseudonym.into(),
            attribute: info.attribute.into(),
        }
    }
}
