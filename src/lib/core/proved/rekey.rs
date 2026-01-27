use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use super::commitments::RekeyFactorCommitments;


/// Second GroupElement is `k*G` if verifiable_rekey with `k` is called.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRekey {
    pub pb: Proof,
    #[cfg(feature = "elgamal3")]
    pub py: Proof,
}

impl VerifiableRekey {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, k: &ScalarNonZero, rng: &mut R) -> Self {
        // Rekey is normally {in.b/k, in.c, k*in.y};
        let (_, pb) = create_proof(&k.invert(), &v.gb, rng);
        #[cfg(feature = "elgamal3")]
        let (_, py) = create_proof(k, &v.gy, rng);
        Self {
            pb,
            #[cfg(feature = "elgamal3")]
            py,
        }
    }
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        commitments: &RekeyFactorCommitments,
    ) -> Option<ElGamal> {
        if self.verify(original, commitments) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    /// Extract the result of the rekey operation from the proof.
    ///
    /// This allows getting the transformed ElGamal value without duplicating data.
    /// The `gc` component is taken from the original since it doesn't change during rekey.
    pub fn result(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: *self.pb,
            gc: original.gc,
            #[cfg(feature = "elgamal3")]
            gy: *self.py,
        }
    }

    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.result(original)
    }
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.reconstruct(original)
    }
    #[must_use]
    fn verify(&self, original: &ElGamal, commitments: &RekeyFactorCommitments) -> bool {
        #[cfg(feature = "elgamal3")]
        return Self::verify_split(
            &original.gb,
            &original.gc,
            &original.gy,
            &commitments.0.val,
            &commitments.0.inv,
            &self.pb,
            &self.py,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split(
            &original.gb,
            &original.gc,
            &commitments.0.val,
            &commitments.0.inv,
            &self.pb,
        )
    }
    #[must_use]
    pub fn verify_rekey(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        commitments: &RekeyFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify(original, commitments)
            && new.gb == *self.pb
            && new.gc == original.gc
            && new.gy == *self.py;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify(original, commitments) && new.gb == *self.pb && new.gc == original.gc;
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        _gc: &GroupElement,
        gy: &GroupElement,
        gk: &GroupElement,
        gki: &GroupElement,
        pb: &Proof,
        py: &Proof,
    ) -> bool {
        verify_proof(gki, gb, pb) && verify_proof(gk, gy, py)
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        _gc: &GroupElement,
        _gk: &GroupElement,
        gki: &GroupElement,
        pb: &Proof,
    ) -> bool {
        verify_proof(gki, gb, pb)
    }

    // Rekey2 methods
    pub fn new2<R: RngCore + CryptoRng>(
        v: &ElGamal,
        from: &ScalarNonZero,
        to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        // Rekey2 is normally {k_from * k_to^-1 * in.B, in.c, k_from^-1 * k_to * in.y};
        let k_from_inv = from.invert();
        let k = k_from_inv * to;
        let (_gki, pb) = create_proof(&k.invert(), &v.gb, rng);
        #[cfg(feature = "elgamal3")]
        let (_gk, py) = create_proof(&k, &v.gy, rng);
        Self {
            pb,
            #[cfg(feature = "elgamal3")]
            py,
        }
    }
    pub fn verified_reconstruct2(
        &self,
        original: &ElGamal,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> Option<ElGamal> {
        if self.verify2(original, rekey2_proof) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    #[must_use]
    fn verify2(&self, original: &ElGamal, rekey2_proof: &Rekey2FactorsProof) -> bool {
        #[cfg(feature = "elgamal3")]
        return Self::verify_split2(
            &original.gb,
            &original.gc,
            &original.gy,
            &self.pb,
            &self.py,
            rekey2_proof,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split2(&original.gb, &original.gc, &self.pb, rekey2_proof)
    }
    #[must_use]
    pub fn verify_rekey2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify2(original, rekey2_proof)
            && new.gb == *self.pb
            && new.gy == *self.py
            && new.gc == original.gc;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify2(original, rekey2_proof) && new.gb == *self.pb && new.gc == original.gc;
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    fn verify_split2(
        gb: &GroupElement,
        _gc: &GroupElement,
        gy: &GroupElement,
        pb: &Proof,
        py: &Proof,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> bool {
        verify_proof(&rekey2_proof.pki, gb, pb) && verify_proof(&rekey2_proof.pk, gy, py)
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify_split2(
        gb: &GroupElement,
        _gc: &GroupElement,
        pb: &Proof,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> bool {
        verify_proof(&rekey2_proof.pki, gb, pb)
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Rekey2FactorsProof {
    #[cfg(feature = "elgamal3")]
    pub pk: Proof,
    pub pki: Proof,
}

impl Rekey2FactorsProof {
    pub fn new<R: RngCore + CryptoRng>(
        from: &ScalarNonZero,
        to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        #[cfg(feature = "elgamal3")]
        let (_gk_to, pk) = create_proof(&from.invert(), &(to * G), rng);
        let (_gki_to, pki) = create_proof(&from, &(to.invert() * G), rng);
        Self {
            #[cfg(feature = "elgamal3")]
            pk,
            pki,
        }
    }
    #[cfg(feature = "elgamal3")]
    pub fn from_proof(
        pk: &Proof,
        pki: &Proof,
        commitments_from: &RekeyFactorCommitments,
        commitments_to: &RekeyFactorCommitments,
    ) -> Option<Self> {
        let x = Self { pk: *pk, pki: *pki };
        if x.verify(commitments_from, commitments_to) {
            Some(x)
        } else {
            None
        }
    }
    #[cfg(not(feature = "elgamal3"))]
    pub fn from_proof(
        pki: &Proof,
        commitments_from: &RekeyFactorCommitments,
        commitments_to: &RekeyFactorCommitments,
    ) -> Option<Self> {
        let x = Self { pki: *pki };
        if x.verify(commitments_from, commitments_to) {
            Some(x)
        } else {
            None
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        commitments_from: &RekeyFactorCommitments,
        commitments_to: &RekeyFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return verify_proof(&commitments_from.0.inv, &commitments_to.0.val, &self.pk)
            && verify_proof(&commitments_from.0.val, &commitments_to.0.inv, &self.pki);
        #[cfg(not(feature = "elgamal3"))]
        verify_proof(&commitments_from.0.val, &commitments_to.0.inv, &self.pki)
    }
}

pub fn verifiable_rekey<R: RngCore + CryptoRng>(
    m: &ElGamal,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekey {
    VerifiableRekey::new(m, k, rng)
}

pub fn verifiable_rekey2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    from: &ScalarNonZero,
    to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekey {
    VerifiableRekey::new2(m, from, to, rng)
}
