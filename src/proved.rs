use crate::arithmetic::*;
use crate::elgamal::*;
use crate::zkps::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct FactorVerifiers {
    pub val: GroupElement,
    pub inv: GroupElement,
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct FactorVerifiersProof(Proof, ScalarNonZero, GroupElement);

impl FactorVerifiers {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, FactorVerifiersProof) {
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
            FactorVerifiersProof(pai, r, gra),
        )
    }
}

impl FactorVerifiersProof {
    #[must_use]
    pub fn verify(&self, verifiers: &FactorVerifiers) -> bool {
        let FactorVerifiers { val: ga, inv: gai } = verifiers;
        verify_proof(gai, &self.2, &self.0) && self.0.n == self.1 * G && self.1 * ga == self.2
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct RekeyFactorVerifiers(FactorVerifiers);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct PseudonymizationFactorVerifiers(FactorVerifiers);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct RekeyFactorVerifiersProof(FactorVerifiersProof);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct PseudonymizationFactorVerifiersProof(FactorVerifiersProof);
impl RekeyFactorVerifiers {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, RekeyFactorVerifiersProof) {
        let (verifiers, proof) = FactorVerifiers::new(a, rng);
        (Self(verifiers), RekeyFactorVerifiersProof(proof))
    }
}

impl PseudonymizationFactorVerifiers {
    pub fn new<R: RngCore + CryptoRng>(
        a: &ScalarNonZero,
        rng: &mut R,
    ) -> (Self, PseudonymizationFactorVerifiersProof) {
        let (verifiers, proof) = FactorVerifiers::new(a, rng);
        (Self(verifiers), PseudonymizationFactorVerifiersProof(proof))
    }
}

#[cfg(not(feature = "elgamal2"))]
//// RERANDOMIZE
// We are re-using some variables from the Proof to reconstruct the Rerandomize operation.
// This way, we only need 1 Proof object (which are fairly large)
pub struct ProvedRerandomize(GroupElement, Proof);

#[cfg(not(feature = "elgamal2"))]
impl ProvedRerandomize {
    pub fn new<R: RngCore + CryptoRng>(original: &ElGamal, r: &ScalarNonZero, rng: &mut R) -> Self {
        // Rerandomize is normally {r * G + in.b, r*in.y + in.c, in.y};
        let (gr, p) = create_proof(r, &original.y, rng);
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
            b: self.0 + original.b,
            c: *self.1 + original.c,
            y: original.y,
        }
    }
    #[must_use]
    fn verify(&self, original: &ElGamal) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &self.0, &self.1)
    }
    #[must_use]
    pub fn verify_rerandomized(&self, original: &ElGamal, new: &ElGamal) -> bool {
        self.verify(original)
            && new.b == self.0 + original.b
            && new.c == *self.1 + original.c
            && new.y == original.y
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

//// RESHUFFLE

#[derive(Eq, PartialEq, Clone, Copy)]
/// GroupElement is `n*G` if prove_reshuffle with `n` is called.
pub struct ProvedReshuffle {
    pub pb: Proof,
    pub pc: Proof,
}

impl ProvedReshuffle {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s: &ScalarNonZero, rng: &mut R) -> Self {
        // Reshuffle is normally {s * in.b, s * in.c, in.y};
        // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same s is used, saving one s*G operation)
        let (_gs, pb) = create_proof(s, &v.b, rng);
        let (_gs, pc) = create_proof(s, &v.c, rng);
        Self { pb, pc }
    }
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        verifiers: &PseudonymizationFactorVerifiers,
    ) -> Option<ElGamal> {
        if self.verify(original, verifiers) {
            #[cfg(not(feature = "elgamal2"))]
            return Some(self.reconstruct(original));
            #[cfg(feature = "elgamal2")]
            Some(self.reconstruct())
        } else {
            None
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.pb,
            c: *self.pc,
            y: original.y,
        }
    }
    #[cfg(feature = "elgamal2")]
    fn reconstruct(&self) -> ElGamal {
        ElGamal {
            b: *self.pb,
            c: *self.pc,
        }
    }
    #[cfg(feature = "unsafe-reconstruct")]
    #[cfg(not(feature = "elgamal2"))]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.reconstruct(original)
    }
    #[cfg(feature = "unsafe-reconstruct")]
    #[cfg(feature = "elgamal2")]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.reconstruct()
    }

    #[must_use]
    fn verify(&self, original: &ElGamal, verifiers: &PseudonymizationFactorVerifiers) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return Self::verify_split(
            &original.b,
            &original.c,
            &original.y,
            &verifiers.val,
            &self.pb,
            &self.pc,
        );
        #[cfg(feature = "elgamal2")]
        Self::verify_split(&original.b, &original.c, &verifiers.val, &self.pb, &self.pc)
    }
    #[must_use]
    pub fn verify_reshuffle(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        verifiers: &PseudonymizationFactorVerifiers,
    ) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return self.verify(original, verifiers)
            && new.b == *self.pb
            && new.c == *self.pc
            && new.y == original.y;
        #[cfg(feature = "elgamal2")]
        return self.verify(original, verifiers) && new.b == *self.pb && new.c == *self.pc;
    }
    #[cfg(not(feature = "elgamal2"))]
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
    #[cfg(feature = "elgamal2")]
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

/// Second GroupElement is `k*G` if prove_rekey with `k` is called.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct ProvedRekey {
    pub pb: Proof,
    #[cfg(not(feature = "elgamal2"))]
    pub py: Proof,
}
impl ProvedRekey {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, k: &ScalarNonZero, rng: &mut R) -> Self {
        // Rekey is normally {in.b/k, in.c, k*in.y};
        let (_, pb) = create_proof(&k.invert(), &v.b, rng);
        #[cfg(not(feature = "elgamal2"))]
        let (_, py) = create_proof(k, &v.y, rng);
        Self {
            pb,
            #[cfg(not(feature = "elgamal2"))]
            py,
        }
    }
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        verifiers: &RekeyFactorVerifiers,
    ) -> Option<ElGamal> {
        if self.verify(original, verifiers) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.pb,
            c: original.c,
            #[cfg(not(feature = "elgamal2"))]
            y: *self.py,
        }
    }
    #[cfg(feature = "unsafe-reconstruct")]
    pub fn unverified_reconstruct(&self, original: &ElGamal) -> ElGamal {
        self.reconstruct(original)
    }
    #[must_use]
    fn verify(&self, original: &ElGamal, verifiers: &RekeyFactorVerifiers) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return Self::verify_split(
            &original.b,
            &original.c,
            &original.y,
            &verifiers.val,
            &verifiers.inv,
            &self.pb,
            &self.py,
        );
        #[cfg(feature = "elgamal2")]
        Self::verify_split(
            &original.b,
            &original.c,
            &verifiers.val,
            &verifiers.inv,
            &self.pb,
        )
    }
    #[must_use]
    pub fn verify_rekey(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        verifiers: &RekeyFactorVerifiers,
    ) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return self.verify(original, verifiers)
            && new.b == *self.pb
            && new.c == original.c
            && new.y == *self.py;
        #[cfg(feature = "elgamal2")]
        return self.verify(original, verifiers) && new.b == self.pb.n && new.c == original.c;
    }
    #[cfg(not(feature = "elgamal2"))]
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
    #[cfg(feature = "elgamal2")]
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
        reshuffle_verifiers: &PseudonymizationFactorVerifiers,
        rekey_verifiers: &RekeyFactorVerifiers,
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
        reshuffle_verifiers: &PseudonymizationFactorVerifiers,
        rekey_verifiers: &RekeyFactorVerifiers,
    ) -> bool {
        verify_proof(&rekey_verifiers.inv, &reshuffle_verifiers.val, &self.pski)
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct ProvedRSK {
    pub pb: Proof,
    pub pc: Proof,
    #[cfg(not(feature = "elgamal2"))]
    pub py: Proof,
}

impl ProvedRSK {
    pub fn new<R: RngCore + CryptoRng>(
        v: &ElGamal,
        s: &ScalarNonZero,
        k: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        // RSK is normally {s * k^-1 * in.b, s * in.c, k * in.y};
        let ki = k.invert();
        let ski = s * ki;
        let (_gski, pb) = create_proof(&ski, &v.b, rng);
        let (_gn, pc) = create_proof(s, &v.c, rng);
        #[cfg(not(feature = "elgamal2"))]
        let (_gk, py) = create_proof(k, &v.y, rng);
        Self {
            pb,
            pc,
            #[cfg(not(feature = "elgamal2"))]
            py,
        }
    }
    pub fn verified_reconstruct(
        &self,
        original: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_verifiers: &PseudonymizationFactorVerifiers,
        rekey_verifiers: &RekeyFactorVerifiers,
    ) -> Option<ElGamal> {
        if self.verify(original, rsk_proof, reshuffle_verifiers, rekey_verifiers) {
            Some(self.reconstruct())
        } else {
            None
        }
    }
    fn reconstruct(&self) -> ElGamal {
        ElGamal {
            b: *self.pb,
            c: *self.pc,
            #[cfg(not(feature = "elgamal2"))]
            y: *self.py,
        }
    }
    #[cfg(feature = "unsafe-reconstruct")]
    pub fn unverified_reconstruct(&self) -> ElGamal {
        self.reconstruct()
    }
    #[must_use]
    fn verify(
        &self,
        original: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_verifiers: &PseudonymizationFactorVerifiers,
        rekey_verifiers: &RekeyFactorVerifiers,
    ) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return Self::verify_split(
            &original.b,
            &original.c,
            &original.y,
            &self.pb,
            &self.pc,
            &self.py,
            rsk_proof,
            reshuffle_verifiers,
            rekey_verifiers,
        );
        #[cfg(feature = "elgamal2")]
        Self::verify_split(
            &original.b,
            &original.c,
            &self.pb,
            &self.pc,
            rsk_proof,
            reshuffle_verifiers,
            rekey_verifiers,
        )
    }
    #[cfg(not(feature = "elgamal2"))]
    #[must_use]
    pub fn verify_rsk(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rsk_proof: &RSKFactorsProof,
        reshuffle_verifiers: &PseudonymizationFactorVerifiers,
        rekey_verifiers: &RekeyFactorVerifiers,
    ) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return self.verify(original, rsk_proof, reshuffle_verifiers, rekey_verifiers)
            && new.b == self.pb.n
            && new.c == self.pc.n
            && new.y == self.py.n;
        #[cfg(feature = "elgamal2")]
        return self.verify(original, rsk_proof, reshuffle_verifiers, rekey_verifiers)
            && new.b == self.pb.n
            && new.c == self.pc.n;
    }
    #[cfg(not(feature = "elgamal2"))]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        gc: &GroupElement,
        gy: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        py: &Proof,
        rsk_proof: &RSKFactorsProof,
        reshuffle_verifiers: &PseudonymizationFactorVerifiers,
        rekey_verifiers: &RekeyFactorVerifiers,
    ) -> bool {
        verify_proof(&rsk_proof.pski, gb, pb)
            && verify_proof(&reshuffle_verifiers.val, gc, pc)
            && verify_proof(&rekey_verifiers.val, gy, py)
    }
    #[cfg(feature = "elgamal2")]
    #[must_use]
    fn verify_split(
        gb: &GroupElement,
        gc: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        rsk_proof: &RSKFactorsProof,
        reshuffle_verifiers: &PseudonymizationFactorVerifiers,
        rekey_verifiers: &RekeyFactorVerifiers,
    ) -> bool {
        verify_proof(&rsk_proof.pski, gb, pb)
            && verify_proof(&reshuffle_verifiers.val, gc, pc)
            && verify_proof(
                &rekey_verifiers.inv,
                &reshuffle_verifiers.val,
                &rsk_proof.pski,
            )
    }
}
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
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
        verifiers_from: &PseudonymizationFactorVerifiers,
        verifiers_to: &PseudonymizationFactorVerifiers,
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
        verifiers_from: &PseudonymizationFactorVerifiers,
        verifiers_to: &PseudonymizationFactorVerifiers,
    ) -> bool {
        verify_proof(&verifiers_from.inv, &verifiers_to.val, &self.ps)
    }
}
impl ProvedReshuffle {
    pub fn new2<R: RngCore + CryptoRng>(
        v: &ElGamal,
        from: &ScalarNonZero,
        to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        // Reshuffle2 is normally {s_from^-1 * s_to * in.b, s_from^-1 * s_to * in.c, in.y};
        // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same s is used, saving one s*G operation)
        let s = from.invert() * to;
        let (_gs, pb) = create_proof(&s, &v.b, rng);
        let (_gs, pc) = create_proof(&s, &v.c, rng);
        Self { pb, pc }
    }
    pub fn verified_reconstruct2(
        &self,
        original: &ElGamal,
        reshuffle2_proof: &Reshuffle2FactorsProof,
    ) -> Option<ElGamal> {
        if self.verify2(original, reshuffle2_proof) {
            #[cfg(not(feature = "elgamal2"))]
            return Some(self.reconstruct(original));
            #[cfg(feature = "elgamal2")]
            Some(self.reconstruct())
        } else {
            None
        }
    }
    #[must_use]
    fn verify2(&self, original: &ElGamal, reshuffle2_proof: &Reshuffle2FactorsProof) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return Self::verify_split2(
            &original.b,
            &original.c,
            &original.y,
            &self.pb,
            &self.pc,
            reshuffle2_proof,
        );
        #[cfg(feature = "elgamal2")]
        Self::verify_split2(
            &original.b,
            &original.c,
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
        #[cfg(not(feature = "elgamal2"))]
        return self.verify2(original, reshuffle2_proof)
            && new.b == self.pb.n
            && new.c == self.pc.n
            && new.y == original.y;
        #[cfg(feature = "elgamal2")]
        return self.verify2(original, reshuffle2_proof)
            && new.b == self.pb.n
            && new.c == self.pc.n;
    }
    #[cfg(not(feature = "elgamal2"))]
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
    #[cfg(feature = "elgamal2")]
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
pub struct Rekey2FactorsProof {
    #[cfg(not(feature = "elgamal2"))]
    pub pk: Proof,
    pub pki: Proof,
}
impl Rekey2FactorsProof {
    pub fn new<R: RngCore + CryptoRng>(
        from: &ScalarNonZero,
        to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        #[cfg(not(feature = "elgamal2"))]
        let (_gk_to, pk) = create_proof(&from.invert(), &(to * G), rng);
        let (_gki_to, pki) = create_proof(&from, &(to.invert() * G), rng);
        Self {
            #[cfg(not(feature = "elgamal2"))]
            pk,
            pki,
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn from_proof(
        pk: &Proof,
        pki: &Proof,
        verifiers_from: &RekeyFactorVerifiers,
        verifiers_to: &RekeyFactorVerifiers,
    ) -> Option<Self> {
        let x = Self { pk: *pk, pki: *pki };
        if x.verify(verifiers_from, verifiers_to) {
            Some(x)
        } else {
            None
        }
    }
    #[cfg(feature = "elgamal2")]
    pub fn from_proof(
        pki: &Proof,
        verifiers_from: &RekeyFactorVerifiers,
        verifiers_to: &RekeyFactorVerifiers,
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
        verifiers_from: &RekeyFactorVerifiers,
        verifiers_to: &RekeyFactorVerifiers,
    ) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return verify_proof(&verifiers_from.inv, &verifiers_to.val, &self.pk)
            && verify_proof(&verifiers_from.val, &verifiers_to.inv, &self.pki);
        #[cfg(feature = "elgamal2")]
        verify_proof(&verifiers_from.val, &verifiers_to.inv, &self.pki)
    }
}

impl ProvedRekey {
    pub fn new2<R: RngCore + CryptoRng>(
        v: &ElGamal,
        from: &ScalarNonZero,
        to: &ScalarNonZero,
        rng: &mut R,
    ) -> Self {
        // Rekey2 is normally {k_from * k_to^-1 * in.B, in.c, k_from^-1 * k_to * in.y};
        let k_from_inv = from.invert();
        let k = k_from_inv * to;
        let (_gki, pb) = create_proof(&k.invert(), &v.b, rng);
        #[cfg(not(feature = "elgamal2"))]
        let (_gk, py) = create_proof(&k, &v.y, rng);
        Self {
            pb,
            #[cfg(not(feature = "elgamal2"))]
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
        #[cfg(not(feature = "elgamal2"))]
        return Self::verify_split2(
            &original.b,
            &original.c,
            &original.y,
            &self.pb,
            &self.py,
            rekey2_proof,
        );
        #[cfg(feature = "elgamal2")]
        Self::verify_split2(&original.b, &original.c, &self.pb, rekey2_proof)
    }
    #[must_use]
    pub fn verify_rekey2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rekey2_proof: &Rekey2FactorsProof,
    ) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return self.verify2(original, rekey2_proof)
            && new.b == self.pb.n
            && new.y == self.py.n
            && new.c == original.c;
        #[cfg(feature = "elgamal2")]
        return self.verify2(original, rekey2_proof) && new.b == self.pb.n && new.c == original.c;
    }
    #[cfg(not(feature = "elgamal2"))]
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
    #[cfg(feature = "elgamal2")]
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
pub struct RSK2FactorsProof {
    pub pski: Proof,
    pub gs: GroupElement,
    #[cfg(not(feature = "elgamal2"))]
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
        #[cfg(not(feature = "elgamal2"))]
        let gk = k * G;
        Self {
            pski,
            gs,
            #[cfg(not(feature = "elgamal2"))]
            gk,
        }
    }
    #[cfg(not(feature = "elgamal2"))]
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
    #[cfg(feature = "elgamal2")]
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
        #[cfg(not(feature = "elgamal2"))]
        return verify_proof(&rekey2_proof.pki.n, &reshuffle2_proof.ps.n, &self.pski)
            && self.gs == reshuffle2_proof.ps.n
            && self.gk == rekey2_proof.pk.n;
        #[cfg(feature = "elgamal2")]
        return verify_proof(&rekey2_proof.pki.n, &reshuffle2_proof.ps.n, &self.pski)
            && self.gs == reshuffle2_proof.ps.n;
    }
}

impl ProvedRSK {
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

        let (_gski, pb) = create_proof(&ski, &v.b, rng);
        let (_gs, pc) = create_proof(&s, &v.c, rng);
        #[cfg(not(feature = "elgamal2"))]
        let (_gk, py) = create_proof(&k, &v.y, rng);
        Self {
            pb,
            pc,
            #[cfg(not(feature = "elgamal2"))]
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
    #[cfg(not(feature = "elgamal2"))]
    #[must_use]
    fn verify2(&self, original: &ElGamal, rsk2_proof: &RSK2FactorsProof) -> bool {
        Self::verify_split2(
            &original.b,
            &original.c,
            &original.y,
            &self.pb,
            &self.pc,
            &self.py,
            rsk2_proof,
        )
    }
    #[cfg(feature = "elgamal2")]
    #[must_use]
    fn verify2(&self, original: &ElGamal, rsk2_proof: &RSK2FactorsProof) -> bool {
        Self::verify_split2(&original.b, &original.c, &self.pb, &self.pc, rsk2_proof)
    }
    #[must_use]
    pub fn verify_rsk2(
        &self,
        original: &ElGamal,
        new: &ElGamal,
        rsk2_proof: &RSK2FactorsProof,
    ) -> bool {
        #[cfg(not(feature = "elgamal2"))]
        return self.verify2(original, rsk2_proof)
            && new.b == self.pb.n
            && new.c == self.pc.n
            && new.y == self.py.n;
        #[cfg(feature = "elgamal2")]
        return self.verify2(original, rsk2_proof) && new.b == self.pb.n && new.c == self.pc.n;
    }
    #[cfg(not(feature = "elgamal2"))]
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
        verify_proof(&rsk2_proof.pski.n, gb, pb)
            && verify_proof(&rsk2_proof.gs, gc, pc)
            && verify_proof(&rsk2_proof.gk, gy, py)
    }
    #[cfg(feature = "elgamal2")]
    #[must_use]
    fn verify_split2(
        gb: &GroupElement,
        gc: &GroupElement,
        pb: &Proof,
        pc: &Proof,
        rsk2_proof: &RSK2FactorsProof,
    ) -> bool {
        verify_proof(&rsk2_proof.pski.n, gb, pb) && verify_proof(&rsk2_proof.gs, gc, pc)
    }
}

#[cfg(not(feature = "elgamal2"))]
pub fn prove_rerandomize<R: RngCore + CryptoRng>(
    m: &ElGamal,
    r: &ScalarNonZero,
    rng: &mut R,
) -> ProvedRerandomize {
    ProvedRerandomize::new(m, r, rng)
}
pub fn prove_reshuffle<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    rng: &mut R,
) -> ProvedReshuffle {
    ProvedReshuffle::new(m, s, rng)
}
pub fn prove_rekey<R: RngCore + CryptoRng>(
    m: &ElGamal,
    k: &ScalarNonZero,
    rng: &mut R,
) -> ProvedRekey {
    ProvedRekey::new(m, k, rng)
}
pub fn prove_rsk<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s: &ScalarNonZero,
    k: &ScalarNonZero,
    rng: &mut R,
) -> ProvedRSK {
    ProvedRSK::new(m, s, k, rng)
}
pub fn prove_reshuffle2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    from: &ScalarNonZero,
    to: &ScalarNonZero,
    rng: &mut R,
) -> ProvedReshuffle {
    ProvedReshuffle::new2(m, from, to, rng)
}
pub fn prove_rekey2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    from: &ScalarNonZero,
    to: &ScalarNonZero,
    rng: &mut R,
) -> ProvedRekey {
    ProvedRekey::new2(m, from, to, rng)
}
pub fn prove_rsk2<R: RngCore + CryptoRng>(
    m: &ElGamal,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
    rng: &mut R,
) -> ProvedRSK {
    ProvedRSK::new2(m, s_from, s_to, k_from, k_to, rng)
}
