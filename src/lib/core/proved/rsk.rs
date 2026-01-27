use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use super::commitments::{PseudonymizationFactorCommitments, RekeyFactorCommitments};
use super::reshuffle::Reshuffle2FactorsProof;
use super::rekey::Rekey2FactorsProof;


#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RSKFactorsProof {
    pub pski: Proof,
}

impl RSKFactorsProof {
    pub fn new<R: RngCore + CryptoRng>(s: &ScalarNonZero, k: &ScalarNonZero, rng: &mut R) -> Self {
        let ki = k.invert();
        let (_gm, pski) = create_proof(&ki, &(s * G), rng);
        Self { pski }
    }
    pub fn from_proof(
        pski: &Proof,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> Option<Self> {
        let x = Self { pski: *pski };
        if x.verify(reshuffle_commitments, rekey_commitments) {
            Some(x)
        } else {
            None
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> bool {
        verify_proof(&rekey_commitments.0.inv, &reshuffle_commitments.0.val, &self.pski)
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRSK {
    pub pb: Proof,
    pub pc: Proof,
    #[cfg(feature = "elgamal3")]
    pub py: Proof,
}

impl VerifiableRSK {
    pub fn new<R: RngCore + CryptoRng>(
        v: &ElGamal,
        s: &ScalarNonZero,
        k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        // RSK is normally {s * k^-1 * in.b, s * in.c, k * in.y};
        let ki = k.invert();
        let ski = s * ki;
        let (_gski, pb) = create_proof(&ski, &v.gb, rng);
        let (_gn, pc) = create_proof(s, &v.gc, rng);
        #[cfg(feature = "elgamal3")]
        let (_gk, py) = create_proof(k, &v.gy, rng);
        Self {
            pb,
            pc,
            #[cfg(feature = "elgamal3")]
            py,
        }
    }
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> Option<ElGamal> {
        if self.verify(original, rsk_proof, reshuffle_commitments, rekey_commitments) {
            Some(self.reconstruct())
        } else {
            None
        }
    }
    /// Extract the result of the RSK operation from the proof.
    ///
    /// This allows getting the transformed ElGamal value without duplicating data.
    pub fn result(&self) -> ElGamal {
        ElGamal {
            gb: *self.pb,
            gc: *self.pc,
            #[cfg(feature = "elgamal3")]
            gy: *self.py,
        }
    }

    fn reconstruct(&self) -> ElGamal {
        self.result()
    }
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.reconstruct()
    }
    #[must_use]
    fn verify(
        &self,
        original: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return Self::verify_split(
            &original.gb,
            &original.gc,
            &original.gy,
            &self.pb,
            &self.pc,
            &self.py,
            rsk_proof,
            reshuffle_commitments,
            rekey_commitments,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split(
            &original.gb,
            &original.gc,
            &self.pb,
            &self.pc,
            rsk_proof,
            reshuffle_commitments,
            rekey_commitments,
        )
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    pub fn verify_rsk(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify(original, rsk_proof, reshuffle_commitments, rekey_commitments)
            && new.gb == *self.pb
            && new.gc == *self.pc
            && new.gy == *self.py;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify(original, rsk_proof, reshuffle_commitments, rekey_commitments)
            && new.gb == *self.pb
            && new.gc == *self.pc;
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    pub fn verify_rsk(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> bool {
        self.verify(original, rsk_proof, reshuffle_commitments, rekey_commitments)
            && new.gb == *self.pb
            && new.gc == *self.pc
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        gc: &GroupElement,
        gy: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        py: &Proof,
        rsk_proof: &RSKFactorsProof,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> bool {
        verify_proof(&rsk_proof.pski, gb, pb)
            && verify_proof(&reshuffle_commitments.0.val, gc, pc)
            && verify_proof(&rekey_commitments.0.val, gy, py)
            && rsk_proof.verify(reshuffle_commitments, rekey_commitments)
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        gc: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        rsk_proof: &RSKFactorsProof,
        reshuffle_commitments: &PseudonymizationFactorCommitments,
        rekey_commitments: &RekeyFactorCommitments,
    ) -> bool {
        verify_proof(&rsk_proof.pski, gb, pb)
            && verify_proof(&reshuffle_commitments.0.val, gc, pc)
            && rsk_proof.verify(reshuffle_commitments, rekey_commitments)
    }

    // RSK2 methods
    pub fn new2<R: RngCore + CryptoRng>(
        v: &ElGamal,
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        // RSK is normally {s * k^-1 * in.b, s * in.c, k * in.y};
        let s = s_from.invert() * s_to;
        let k = k_from.invert() * k_to;
        let ki = k.invert();
        let ski = s * ki;

        let (_gski, pb) = create_proof(&ski, &v.gb, rng);
        let (_gs, pc) = create_proof(&s, &v.gc, rng);
        #[cfg(feature = "elgamal3")]
        let (_gk, py) = create_proof(&k, &v.gy, rng);
        Self {
            pb,
            pc,
            #[cfg(feature = "elgamal3")]
            py,
        }
    }
    pub fn verified_reconstruct2(
        &self,
        original: &ElGamal,
        rsk2_proof: &RSK2FactorsProof,
    ) -> Option<ElGamal> {
        if self.verify2(original, rsk2_proof) {
            Some(self.reconstruct())
        } else {
            None
        }
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    fn verify2(&self, original: &ElGamal, rsk2_proof: &RSK2FactorsProof) -> bool {
        Self::verify_split2(
            &original.gb,
            &original.gc,
            &original.gy,
            &self.pb,
            &self.pc,
            &self.py,
            rsk2_proof,
        )
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify2(&self, original: &ElGamal, rsk2_proof: &RSK2FactorsProof) -> bool {
        Self::verify_split2(&original.gb, &original.gc, &self.pb, &self.pc, rsk2_proof)
    }
    #[must_use]
    pub fn verify_rsk2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rsk2_proof: &RSK2FactorsProof,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify2(original, rsk2_proof)
            && new.gb == *self.pb
            && new.gc == *self.pc
            && new.gy == *self.py;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify2(original, rsk2_proof) && new.gb == *self.pb && new.gc == *self.pc;
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    fn verify_split2(
        gb: &GroupElement,
        gc: &GroupElement,
        gy: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        py: &Proof,
        rsk2_proof: &RSK2FactorsProof,
    ) -> bool {
        verify_proof(&rsk2_proof.pski, gb, pb)
            && verify_proof(&rsk2_proof.gs, gc, pc)
            && verify_proof(&rsk2_proof.gk, gy, py)
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify_split2(
        gb: &GroupElement,
        gc: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        rsk2_proof: &RSK2FactorsProof,
    ) -> bool {
        verify_proof(&rsk2_proof.pski, gb, pb) && verify_proof(&rsk2_proof.gs, gc, pc)
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RSK2FactorsProof {
    pub pski: Proof,
    pub gs: GroupElement,
    #[cfg(feature = "elgamal3")]
    pub gk: GroupElement,
}

impl RSK2FactorsProof {
    pub fn new<R: RngCore + CryptoRng>(
        s_from: &ScalarNonZero,
        s_to: &ScalarNonZero,
        k_from: &ScalarNonZero,
        k_to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        let gs = s_from.invert() * s_to * G;
        let k = k_from.invert() * k_to;
        let (_gm, pski) = create_proof(&k.invert(), &gs, rng);
        #[cfg(feature = "elgamal3")]
        let gk = k * G;
        Self {
            pski,
            gs,
            #[cfg(feature = "elgamal3")]
            gk,
        }
    }
    #[cfg(feature = "elgamal3")]
    pub fn from_proof(
        pski: &Proof,
        gs: &GroupElement,
        gk: &GroupElement,
        reshuffle2_proof: &Reshuffle2FactorsProof,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> Option<Self> {
        let x = Self {
            pski: *pski,
            gs: *gs,
            gk: *gk,
        };
        if x.verify(&reshuffle2_proof, &rekey2_proof) {
            Some(x)
        } else {
            None
        }
    }
    #[cfg(not(feature = "elgamal3"))]
    pub fn from_proof(
        pski: &Proof,
        gs: &GroupElement,
        reshuffle2_proof: &Reshuffle2FactorsProof,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> Option<Self> {
        let x = Self {
            pski: *pski,
            gs: *gs,
        };
        if x.verify(&reshuffle2_proof, &rekey2_proof) {
            Some(x)
        } else {
            None
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        reshuffle2_proof: &Reshuffle2FactorsProof,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return verify_proof(&rekey2_proof.pki, &reshuffle2_proof.ps, &self.pski)
            && self.gs == *reshuffle2_proof.ps
            && self.gk == *rekey2_proof.pk;
        #[cfg(not(feature = "elgamal3"))]
        return verify_proof(&rekey2_proof.pki, &reshuffle2_proof.ps, &self.pski)
            && self.gs == *reshuffle2_proof.ps;
    }
}

pub fn verifiable_rsk<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRSK {
    VerifiableRSK::new(m, s, k, rng)
}

pub fn verifiable_rsk2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRSK {
    VerifiableRSK::new2(m, s_from, s_to, k_from, k_to, rng)
}
