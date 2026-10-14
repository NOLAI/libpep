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

use crate::elgamal::arithmetic::group::Group;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Forward commitment `A = a·G` to a factor scalar `a`.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct FactorCommitment<G: Group>(pub G::Element);

impl<G: Group> FactorCommitment<G> {
    /// Build a commitment to scalar `a`: `A = a · G`.
    pub fn new(a: &G::Scalar) -> Self {
        Self(*a * G::generator())
    }

    /// The committed group element `A`.
    pub fn point(&self) -> G::Element {
        self.0
    }
}

/// Commitment to a rekey factor `k`: `K = k·G`.
///
/// Structurally identical to [`PseudonymizationFactorCommitment`]; the two types exist to
/// prevent mixing up rekey and reshuffle commitments at call sites. The wrappers deliberately
/// do not convert into each other or into [`FactorCommitment`]: the group element is reached
/// through the explicit [`point`](Self::point), which is meant to surface in code review.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct RekeyFactorCommitment<G: Group>(pub FactorCommitment<G>);

/// Commitment to a pseudonymization (reshuffle) factor `s`: `S = s·G`. See
/// [`RekeyFactorCommitment`] for the phantom-type rationale.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct PseudonymizationFactorCommitment<G: Group>(pub FactorCommitment<G>);

macro_rules! impl_commitment {
    ($t:ident) => {
        impl<G: Group> $t<G> {
            /// Build a commitment to scalar `a`: `A = a · G`.
            pub fn new(a: &G::Scalar) -> Self {
                Self(FactorCommitment::new(a))
            }

            /// The committed group element `A`.
            pub fn point(&self) -> G::Element {
                self.0.point()
            }
        }
    };
}

impl_commitment!(RekeyFactorCommitment);
impl_commitment!(PseudonymizationFactorCommitment);
