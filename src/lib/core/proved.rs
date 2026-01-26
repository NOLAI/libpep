use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::ElGamal;
use crate::core::zkps::{create_proof, create_proofs_same_scalar, verify_proof, Proof};

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
    pub fn verify(&self, verifiers: &FactorCommitments) -> bool {
        let FactorCommitments { val: ga, inv: gai } = verifiers;
        verify_proof(gai, &self.2, &self.0) && self.0.n == self.1 * G && self.1 * ga == self.2
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RekeyFactorCommitments(FactorCommitments);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PseudonymizationFactorCommitments(FactorCommitments);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RekeyFactorCommitmentsProof(FactorCommitmentsProof);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PseudonymizationFactorCommitmentsProof(FactorCommitmentsProof);
impl RekeyFactorCommitments {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, RekeyFactorCommitmentsProof) {
        let (verifiers, proof) = FactorCommitments::new(a, rng);
        (Self(verifiers), RekeyFactorCommitmentsProof(proof))
    }
}

impl PseudonymizationFactorCommitments {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, PseudonymizationFactorCommitmentsProof) {
        let (verifiers, proof) = FactorCommitments::new(a, rng);
        (Self(verifiers), PseudonymizationFactorCommitmentsProof(proof))
    }
}

#[cfg(feature = "elgamal3")]
/// RERANDOMIZE
// We are re-using some variables from the Proof to reconstruct the Rerandomize operation.
// This way, we only need 1 Proof object (which are fairly large)
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableRerandomize(GroupElement, Proof);

#[cfg(feature = "elgamal3")]
impl VerifiableRerandomize {
    pub fn new<R: RngCore + CryptoRng>(original: &ElGamal, r: &ScalarNonZero, rng: &mut R) -> Self {
        // Rerandomize is normally {r * G + in.b, r*in.y + in.c, in.y};
        let (gr, p) = create_proof(r, &original.gy, rng);
        Self(gr, p)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal) -> Option<ElGamal> {
        if self.verify(original) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: self.0 + original.gb,
            gc: *self.1 + original.gc,
            gy: original.gy,
        }
    }
    #[must_use]
    fn verify(&self, original: &ElGamal) -> bool {
        Self::verify_split(&original.gb, &original.gc, &original.gy, &self.0, &self.1)
    }
    #[must_use]
    pub fn verify_rerandomized(&self, original: &ElGamal, new: &ElGamal) -> bool {
        self.verify(original)
            && new.gb == self.0 + original.gb
            && new.gc == *self.1 + original.gc
            && new.gy == original.gy
    }
    #[must_use]
    fn verify_split(
        _gb: &GroupElement,
        _gc: &GroupElement,
        gy: &GroupElement,
        gr: &GroupElement,
        p: &Proof,
    ) -> bool {
        // slightly different from the others, as we reuse the structure of a standard proof to reconstruct the Rerandomize operation after sending
        verify_proof(gr, gy, p)
    }
}

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
        verifiers: &PseudonymizationFactorCommitments,
    ) -> Option<ElGamal> {
        if self.verify(original, verifiers) {
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
    fn verify(&self, original: &ElGamal, verifiers: &PseudonymizationFactorCommitments) -> bool {
        #[cfg(feature = "elgamal3")]
        return Self::verify_split(
            &original.gb,
            &original.gc,
            &original.gy,
            &verifiers.0.val,
            &self.pb,
            &self.pc,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split(&original.gb, &original.gc, &verifiers.0.val, &self.pb, &self.pc)
    }
    #[must_use]
    pub fn verify_reshuffle(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        verifiers: &PseudonymizationFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify(original, verifiers)
            && new.gb == *self.pb
            && new.gc == *self.pc
            && new.gy == original.gy;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify(original, verifiers) && new.gb == *self.pb && new.gc == *self.pc;
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
}

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
        verifiers: &RekeyFactorCommitments,
    ) -> Option<ElGamal> {
        if self.verify(original, verifiers) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            gb: *self.pb,
            gc: original.gc,
            #[cfg(feature = "elgamal3")]
            gy: *self.py,
        }
    }
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.reconstruct(original)
    }
    #[must_use]
    fn verify(&self, original: &ElGamal, verifiers: &RekeyFactorCommitments) -> bool {
        #[cfg(feature = "elgamal3")]
        return Self::verify_split(
            &original.gb,
            &original.gc,
            &original.gy,
            &verifiers.0.val,
            &verifiers.0.inv,
            &self.pb,
            &self.py,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split(
            &original.gb,
            &original.gc,
            &verifiers.0.val,
            &verifiers.0.inv,
            &self.pb,
        )
    }
    #[must_use]
    pub fn verify_rekey(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        verifiers: &RekeyFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify(original, verifiers)
            && new.gb == *self.pb
            && new.gc == original.gc
            && new.gy == *self.py;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify(original, verifiers) && new.gb == *self.pb && new.gc == original.gc;
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
}
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
        reshuffle_verifiers: &PseudonymizationFactorCommitments,
        rekey_verifiers: &RekeyFactorCommitments,
    ) -> Option<Self> {
        let x = Self { pski: *pski };
        if x.verify(reshuffle_verifiers, rekey_verifiers) {
            Some(x)
        } else {
            None
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        reshuffle_verifiers: &PseudonymizationFactorCommitments,
        rekey_verifiers: &RekeyFactorCommitments,
    ) -> bool {
        verify_proof(&rekey_verifiers.0.inv, &reshuffle_verifiers.0.val, &self.pski)
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
        reshuffle_verifiers: &PseudonymizationFactorCommitments,
        rekey_verifiers: &RekeyFactorCommitments,
    ) -> Option<ElGamal> {
        if self.verify(original, rsk_proof, reshuffle_verifiers, rekey_verifiers) {
            Some(self.reconstruct())
        } else {
            None
        }
    }
    fn reconstruct(&self) -> ElGamal {
        ElGamal {
            gb: *self.pb,
            gc: *self.pc,
            #[cfg(feature = "elgamal3")]
            gy: *self.py,
        }
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
        reshuffle_verifiers: &PseudonymizationFactorCommitments,
        rekey_verifiers: &RekeyFactorCommitments,
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
            reshuffle_verifiers,
            rekey_verifiers,
        );
        #[cfg(not(feature = "elgamal3"))]
        Self::verify_split(
            &original.gb,
            &original.gc,
            &self.pb,
            &self.pc,
            rsk_proof,
            reshuffle_verifiers,
            rekey_verifiers,
        )
    }
    #[cfg(feature = "elgamal3")]
    #[must_use]
    pub fn verify_rsk(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_verifiers: &PseudonymizationFactorCommitments,
        rekey_verifiers: &RekeyFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return self.verify(original, rsk_proof, reshuffle_verifiers, rekey_verifiers)
            && new.gb == *self.pb
            && new.gc == *self.pc
            && new.gy == *self.py;
        #[cfg(not(feature = "elgamal3"))]
        return self.verify(original, rsk_proof, reshuffle_verifiers, rekey_verifier)
            && new.gb == *self.pb
            && new.gc == *self.pc;
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
        reshuffle_verifiers: &PseudonymizationFactorCommitments,
        rekey_verifiers: &RekeyFactorCommitments,
    ) -> bool {
        verify_proof(&rsk_proof.pski, gb, pb)
            && verify_proof(&reshuffle_verifiers.0.val, gc, pc)
            && verify_proof(&rekey_verifiers.0.val, gy, py)
    }
    #[cfg(not(feature = "elgamal3"))]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        gc: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        rsk_proof: &RSKFactorsProof,
        reshuffle_verifiers: &PseudonymizationFactorCommitments,
        rekey_verifiers: &RekeyFactorCommitments,
    ) -> bool {
        verify_proof(&rsk_proof.pski, gb, pb)
            && verify_proof(&reshuffle_verifiers.0.val, gc, pc)
            && verify_proof(
                &rekey_verifiers.0.inv,
                &reshuffle_verifiers.0.val,
                &rsk_proof.pski,
            )
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
        verifiers_from: &PseudonymizationFactorCommitments,
        verifiers_to: &PseudonymizationFactorCommitments,
    ) -> Option<Self> {
        let x = Self { ps: *ps };
        if x.verify(&verifiers_from, &verifiers_to) {
            Some(x)
        } else {
            None
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        verifiers_from: &PseudonymizationFactorCommitments,
        verifiers_to: &PseudonymizationFactorCommitments,
    ) -> bool {
        verify_proof(&verifiers_from.0.inv, &verifiers_to.0.val, &self.ps)
    }
}
impl VerifiableReshuffle {
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
        verifiers_from: &RekeyFactorCommitments,
        verifiers_to: &RekeyFactorCommitments,
    ) -> Option<Self> {
        let x = Self { pk: *pk, pki: *pki };
        if x.verify(verifiers_from, verifiers_to) {
            Some(x)
        } else {
            None
        }
    }
    #[cfg(not(feature = "elgamal3"))]
    pub fn from_proof(
        pki: &Proof,
        verifiers_from: &RekeyFactorCommitments,
        verifiers_to: &RekeyFactorCommitments,
    ) -> Option<Self> {
        let x = Self { pki: *pki };
        if x.verify(&verifiers_from, &verifiers_to) {
            Some(x)
        } else {
            None
        }
    }
    #[must_use]
    pub fn verify(
        &self,
        verifiers_from: &RekeyFactorCommitments,
        verifiers_to: &RekeyFactorCommitments,
    ) -> bool {
        #[cfg(feature = "elgamal3")]
        return verify_proof(&verifiers_from.0.inv, &verifiers_to.0.val, &self.pk)
            && verify_proof(&verifiers_from.0.val, &verifiers_to.0.inv, &self.pki);
        #[cfg(not(feature = "elgamal3"))]
        verify_proof(&verifiers_from.0.val, &verifiers_to.0.inv, &self.pki)
    }
}

impl VerifiableRekey {
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

impl VerifiableRSK {
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

#[cfg(feature = "elgamal3")]
pub fn verifiable_rerandomize<R: RngCore + CryptoRng>(
    m: &ElGamal,
    r: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRerandomize {
    VerifiableRerandomize::new(m, r, rng)
}
pub fn verifiable_reshuffle<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffle {
    VerifiableReshuffle::new(m, s, rng)
}
pub fn verifiable_rekey<R: RngCore + CryptoRng>(
    m: &ElGamal,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekey {
    VerifiableRekey::new(m, k, rng)
}
pub fn verifiable_rsk<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    k: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRSK {
    VerifiableRSK::new(m, s, k, rng)
}
pub fn verifiable_reshuffle2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    from: &ScalarNonZero,
    to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableReshuffle {
    VerifiableReshuffle::new2(m, from, to, rng)
}
pub fn verifiable_rekey2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    from: &ScalarNonZero,
    to: &ScalarNonZero,
    rng: &mut R,
) -> VerifiableRekey {
    VerifiableRekey::new2(m, from, to, rng)
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
