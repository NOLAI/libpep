//! Verifiable variants of the records data-layer operations.
//!
//! Mirrors [`crate::data::records`].
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`RecordTranscryptionProof`](generic::RecordTranscryptionProof) over ristretto255.
pub type RecordTranscryptionProof = generic::RecordTranscryptionProof<Ristretto255>;
/// The [`LongRecordTranscryptionProof`](generic::LongRecordTranscryptionProof) over ristretto255.
#[cfg(feature = "long")]
pub type LongRecordTranscryptionProof = generic::LongRecordTranscryptionProof<Ristretto255>;
/// The [`RecordTranscryptionBatchProof`](generic::RecordTranscryptionBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type RecordTranscryptionBatchProof = generic::RecordTranscryptionBatchProof<Ristretto255>;
/// The [`LongRecordTranscryptionBatchProof`](generic::LongRecordTranscryptionBatchProof) over ristretto255.
#[cfg(all(feature = "batch", feature = "long"))]
pub type LongRecordTranscryptionBatchProof =
    generic::LongRecordTranscryptionBatchProof<Ristretto255>;
