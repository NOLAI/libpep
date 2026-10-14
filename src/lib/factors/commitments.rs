//! Commitment types for verifiable transcryption.
//!
//! With the forward-direction constructions, a "commitment" to a factor is a single group
//! element `A = a·G`; no separate proof of well-formedness is required because every
//! verifiable operation proves a relation against `A` directly.
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`VerifiablePseudonymizationCommitment`](generic::VerifiablePseudonymizationCommitment)
/// over ristretto255.
pub type VerifiablePseudonymizationCommitment =
    generic::VerifiablePseudonymizationCommitment<Ristretto255>;
/// The [`VerifiableRekeyCommitment`](generic::VerifiableRekeyCommitment) over ristretto255.
pub type VerifiableRekeyCommitment = generic::VerifiableRekeyCommitment<Ristretto255>;
/// The [`VerifiableTranscryptionCommitment`](generic::VerifiableTranscryptionCommitment) over
/// ristretto255.
pub type VerifiableTranscryptionCommitment =
    generic::VerifiableTranscryptionCommitment<Ristretto255>;
