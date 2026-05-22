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
use derive_more::{Deref, From};
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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RekeyFactorCommitment(pub FactorCommitment);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
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
