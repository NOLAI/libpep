use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::zkps::{create_proof, verify_proof, Proof};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FactorCommitments {
    pub val: GroupElement,
    pub inv: GroupElement,
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FactorCommitmentsProof(Proof, ScalarNonZero, GroupElement);

impl FactorCommitments {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, FactorCommitmentsProof) {
        let r = ScalarNonZero::random(rng);
        let gra = a * r * G;
        let (gai, pai) = create_proof(&a.invert(), &gra, rng);
        // Checking pki.n == gr proves that a.invert()*a == 1.
        // Assume a'^-1 * (a*r*G) = r*G, then a = a' trivially holds for any a, a', r
        (
            Self {
                val: a * G,
                inv: gai,
            },
            FactorCommitmentsProof(pai, r, gra),
        )
    }

    pub fn reversed(&self) -> Self {
        Self {
            val: self.inv,
            inv: self.val,
        }
    }
}

impl FactorCommitmentsProof {
    #[must_use]
    pub fn verify(&self, commitments: &FactorCommitments) -> bool {
        let FactorCommitments { val: ga, inv: gai } = commitments;
        verify_proof(gai, &self.2, &self.0) && self.0.n == self.1 * G && self.1 * ga == self.2
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RekeyFactorCommitments(pub(crate) FactorCommitments);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PseudonymizationFactorCommitments(pub(crate) FactorCommitments);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RekeyFactorCommitmentsProof(pub(crate) FactorCommitmentsProof);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PseudonymizationFactorCommitmentsProof(pub(crate) FactorCommitmentsProof);

impl RekeyFactorCommitments {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, RekeyFactorCommitmentsProof) {
        let (commitments, proof) = FactorCommitments::new(a, rng);
        (Self(commitments), RekeyFactorCommitmentsProof(proof))
    }
}

impl PseudonymizationFactorCommitments {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, PseudonymizationFactorCommitmentsProof) {
        let (commitments, proof) = FactorCommitments::new(a, rng);
        (Self(commitments), PseudonymizationFactorCommitmentsProof(proof))
    }
}
