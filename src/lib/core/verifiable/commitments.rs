//! Public commitments to verifiable-transcryption factors.
//!
//! A commitment to a scalar factor `a` is simply the forward group element
//! `A = a·G`. There is no separate "inverse" commitment `a⁻¹·G`: every
//! verifiable operation proves a forward relation against `A`, so the bridge
//! between forward and inverse commitments is no longer needed.
//!
//! Validity of a commitment value (e.g. that it is not trivially weak) is
//! responsibility of the verifier; no zero-knowledge proof of well-formedness
//! is required.

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Forward commitment `A = a·G` to a factor scalar `a`.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FactorCommitment(pub GroupElement);

impl FactorCommitment {
    /// Build a commitment to scalar `a`: `A = a · G`.
    pub fn new(a: &ScalarNonZero) -> Self {
        Self(a * G)
    }
}

/// Commitment to a rekey factor `k`: `K = k·G`.
///
/// Structurally identical to [`PseudonymizationFactorCommitment`] — the two
/// types exist as phantom-types to prevent mixing up rekey and reshuffle
/// commitments at call sites. The wrappers intentionally do **not** implement
/// `From`/`Deref` against each other or against [`FactorCommitment`]: crossing
/// the type boundary requires an explicit field access (`.0`), which is meant
/// to surface in code review.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RekeyFactorCommitment(pub FactorCommitment);

/// Commitment to a pseudonymization (reshuffle) factor `s`: `S = s·G`. See
/// [`RekeyFactorCommitment`] for the phantom-type rationale.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PseudonymizationFactorCommitment(pub FactorCommitment);

impl RekeyFactorCommitment {
    pub fn new(a: &ScalarNonZero) -> Self {
        Self(FactorCommitment::new(a))
    }
}

impl PseudonymizationFactorCommitment {
    pub fn new(a: &ScalarNonZero) -> Self {
        Self(FactorCommitment::new(a))
    }
}
