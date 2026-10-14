//! Verifiable variants of the long data-layer operations.
//!
//! Mirrors [`crate::data::long`].
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`LongPseudonymPseudonymizationProof`](generic::LongPseudonymPseudonymizationProof) over ristretto255.
pub type LongPseudonymPseudonymizationProof =
    generic::LongPseudonymPseudonymizationProof<Ristretto255>;
/// The [`LongPseudonymRekeyProof`](generic::LongPseudonymRekeyProof) over ristretto255.
pub type LongPseudonymRekeyProof = generic::LongPseudonymRekeyProof<Ristretto255>;
/// The [`LongAttributeRekeyProof`](generic::LongAttributeRekeyProof) over ristretto255.
pub type LongAttributeRekeyProof = generic::LongAttributeRekeyProof<Ristretto255>;
/// The [`LongPseudonymPseudonymizationBatchProof`](generic::LongPseudonymPseudonymizationBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type LongPseudonymPseudonymizationBatchProof =
    generic::LongPseudonymPseudonymizationBatchProof<Ristretto255>;
/// The [`LongPseudonymRekeyBatchProof`](generic::LongPseudonymRekeyBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type LongPseudonymRekeyBatchProof = generic::LongPseudonymRekeyBatchProof<Ristretto255>;
/// The [`LongAttributeRekeyBatchProof`](generic::LongAttributeRekeyBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type LongAttributeRekeyBatchProof = generic::LongAttributeRekeyBatchProof<Ristretto255>;
