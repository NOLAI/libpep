//! Verifiable variants of the simple data-layer operations.
//!
//! Mirrors [`crate::data::simple`]: each non-verifiable operation
//! ([`Pseudonymizable`](crate::data::traits::Pseudonymizable),
//! [`Rekeyable`](crate::data::traits::Rekeyable)) has a verifiable
//! counterpart here that produces a data-layer proof wrapper around the
//! corresponding core ZKP.
//!
//! Each wrapper carries a core ZKP proof along with the data-type identity
//! of the operation it belongs to. Inherent methods (bare verb names)
//! provide the verifier-side API. The wrappers also implement the
//! appropriate `Verifiable*Proof` trait (rekey / pseudonymization) so
//! they work polymorphically with [`Verifier`](crate::verifier::Verifier).
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`PseudonymPseudonymizationProof`](generic::PseudonymPseudonymizationProof) over ristretto255.
pub type PseudonymPseudonymizationProof = generic::PseudonymPseudonymizationProof<Ristretto255>;
/// The [`PseudonymRekeyProof`](generic::PseudonymRekeyProof) over ristretto255.
pub type PseudonymRekeyProof = generic::PseudonymRekeyProof<Ristretto255>;
/// The [`AttributeRekeyProof`](generic::AttributeRekeyProof) over ristretto255.
pub type AttributeRekeyProof = generic::AttributeRekeyProof<Ristretto255>;
/// The [`PseudonymPseudonymizationBatchProof`](generic::PseudonymPseudonymizationBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type PseudonymPseudonymizationBatchProof =
    generic::PseudonymPseudonymizationBatchProof<Ristretto255>;
/// The [`PseudonymRekeyBatchProof`](generic::PseudonymRekeyBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type PseudonymRekeyBatchProof = generic::PseudonymRekeyBatchProof<Ristretto255>;
/// The [`AttributeRekeyBatchProof`](generic::AttributeRekeyBatchProof) over ristretto255.
#[cfg(feature = "batch")]
pub type AttributeRekeyBatchProof = generic::AttributeRekeyBatchProof<Ristretto255>;
