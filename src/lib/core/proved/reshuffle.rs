use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, create_proofs_same_scalar, verify_proof, Proof};
use super::commitments::PseudonymizationFactorCommitments;

/// RESHUFFLE

#[derive(Eq, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// GroupElement is `n*G` if verifiable_reshuffle with `n` is called.
pub struct VerifiableReshuffle {
    pub pb: Proof,
    pub pc: Proof,
}

impl VerifiableReshuffle {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s: &ScalarNonZero, rng: &mut R) -> Self {
        // Reshuffle is normally {s * in.b, s * in.c, in.y};
        let (_gs, pb, pc) = create_proofs_same_scalar(s, &v.gb, &v.gc, rng);
        Self { pb, pc }
    }
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        commitments: &PseudonymizationFactorCommitments,
    ) -> Option<ElGamal> {
        if self.verify(original, commitments) {
            #[cfg(feature = "elgamal3")]
            return Some(self.reconstruct(original));
            #[cfg(not(feature = "elgamal3"))]
            Some(self.reconstruct())
        } else {
            None
        }
    }
    #[cfg(feature = "elgamal3")]
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: *self.pb,
            gc: *self.pc,
            gy: original.gy,
        }
    }
    #[cfg(not(feature = "elgamal3"))]
    fn reconstruct(&self) -> ElGamal {
        ElGamal {
            gb: *self.pb,
            gc: *self.pc,
        }
    }
    #[cfg(feature = "insecure")]
    #[cfg(feature = "elgamal3")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.reconstruct(original)
    }
    #[cfg(feature = "insecure")]
    #[cfg(not(feature = "elgamal3"))]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.reconstruct()
    }

    #[must_use]
    fn verify(&self, original: &ElGamal, commitments: &PseudonymizationFactorCommitments) -> bool {
        #[cfg(feature = "elgamal3")]
        return Self::verify_split(
            &original.gb,
            &original.gc,
            &original.gy,
            &commitments.0.val,
            &self.pb,
            &self.pc,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split(&original.gb, &original.gc, &commitments.0.val, &self.pb, &self.pc)
    }
    #[must_use]
    pub fn verify_reshuffle(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        commitments: &PseudonymizationFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify(original, commitments)
            && new.gb == *self.pb
            && new.gc == *self.pc
            && new.gy == original.gy;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify(original, commitments) && new.gb == *self.pb && new.gc == *self.pc;
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        gc: &GroupElement,
        _gy: &GroupElement,
        gn: &GroupElement,
        pb: &Proof,
        pc: &Proof,
    ) -> bool {
        verify_proof(gn, gb, pb) && verify_proof(gn, gc, pc)
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        gc: &GroupElement,
        gn: &GroupElement,
        pb: &Proof,
        pc: &Proof,
    ) -> bool {
        verify_proof(gn, gb, pb) && verify_proof(gn, gc, pc)
    }

    // Reshuffle2 methods
    pub fn new2<R: RngCore + CryptoRng>(
        v: &ElGamal,
        from: &ScalarNonZero,
        to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        // Reshuffle2 is normally {s_from^-1 * s_to * in.b, s_from^-1 * s_to * in.c, in.y};
        let s = from.invert() * to;
        let (_gs, pb, pc) = create_proofs_same_scalar(&s, &v.gb, &v.gc, rng);
        Self { pb, pc }
    }
    pub fn verified_reconstruct2(
        &self,
        original: &ElGamal,
        reshuffle2_proof: &Reshuffle2FactorsProof,
    ) -> Option<ElGamal> {
        if self.verify2(original, reshuffle2_proof) {
            #[cfg(feature = "elgamal3")]
            return Some(self.reconstruct(original));
            #[cfg(not(feature = "elgamal3"))]
            Some(self.reconstruct())
        } else {
            None
        }
    }
    #[must_use]
    fn verify2(&self, original: &ElGamal, reshuffle2_proof: &Reshuffle2FactorsProof) -> bool {
        #[cfg(feature = "elgamal3")]
        return Self::verify_split2(
            &original.gb,
            &original.gc,
            &original.gy,
            &self.pb,
            &self.pc,
            reshuffle2_proof,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split2(
            &original.gb,
            &original.gc,
            &self.pb,
            &self.pc,
            reshuffle2_proof,
        )
    }
    #[must_use]
    pub fn verify_reshuffled2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        reshuffle2_proof: &Reshuffle2FactorsProof,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify2(original, reshuffle2_proof)
            && new.gb == *self.pb
            && new.gc == *self.pc
            && new.gy == original.gy;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify2(original, reshuffle2_proof)
            && new.gb == *self.pb
            && new.gc == *self.pc;
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    fn verify_split2(
        gb: &GroupElement,
        gc: &GroupElement,
        _gy: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        reshuffle2_proof: &Reshuffle2FactorsProof,
    ) -> bool {
        // ps is needed as proof that s is constructed as s_from.invert() * s_t
        verify_proof(&reshuffle2_proof.ps, gb, pb) && verify_proof(&reshuffle2_proof.ps, gc, pc)
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify_split2(
        gb: &GroupElement,
        gc: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        reshuffle2_proof: &Reshuffle2FactorsProof,
    ) -> bool {
        // ps is needed as proof that s is constructed as s_from.invert() * s_t
        verify_proof(&reshuffle2_proof.ps, gb, pb) && verify_proof(&reshuffle2_proof.ps, gc, pc)
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Reshuffle2FactorsProof {
    pub ps: Proof,
}

impl Reshuffle2FactorsProof {
    pub fn new<R: RngCore + CryptoRng>(
        from: &ScalarNonZero,
        to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let (_gs, ps) = create_proof(&from.invert(), &(to * G), rng);
        Self { ps }
    }
    pub fn from_proof(
        ps: &Proof,
        commitments_from: &PseudonymizationFactorCommitments,
        commitments_to: &PseudonymizationFactorCommitments,
    ) -> Option<Self> {
        let x = Self { ps: *ps };
        if x.verify(commitments_from, commitments_to) {
            Some(x)
        } else {
            None
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        commitments_from: &PseudonymizationFactorCommitments,
        commitments_to: &PseudonymizationFactorCommitments,
    ) -> bool {
        verify_proof(&commitments_from.0.inv, &commitments_to.0.val, &self.ps)
    }
}

pub fn verifiable_reshuffle<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffle {
    VerifiableReshuffle::new(m, s, rng)
}

pub fn verifiable_reshuffle2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    from: &ScalarNonZero,
    to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffle {
    VerifiableReshuffle::new2(m, from, to, rng)
}
