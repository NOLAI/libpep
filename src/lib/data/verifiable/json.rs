//! Verifiable variants of the JSON data-layer operations.
//!
//! Mirrors [`crate::data::json::data`].
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`JsonTranscryptionProof`](generic::JsonTranscryptionProof) over ristretto255.
pub type JsonTranscryptionProof = generic::JsonTranscryptionProof<Ristretto255>;
/// The [`JsonTranscryptionBatchProof`](generic::JsonTranscryptionBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type JsonTranscryptionBatchProof = generic::JsonTranscryptionBatchProof<Ristretto255>;
