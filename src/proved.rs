use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::*;
use crate::elgamal::*;
use crate::zkps::*;


#[derive(Eq, PartialEq, Clone, Copy)]
pub struct FactorVerifiers(pub GroupElement, pub GroupElement);
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct FactorVerifiersProof(Proof, ScalarNonZero, GroupElement); // TODO maybe we shouldnt send the scalar but only the group element associated to the scalar, since we should never send scalars in the clear

impl FactorVerifiers {
    pub fn new<R: RngCore + CryptoRng>(a: &ScalarNonZero, rng: &mut R) -> (Self, FactorVerifiersProof) {
        let r = ScalarNonZero::random(rng);
        let gra = a * r * G;
        let (gai, pai) = create_proof(&a.invert(), &gra, rng);
        // Checking pki.n == gr proves that a.invert()*a == 1.
        // Assume a'^-1 * (a*r*G) = r*G, then a = a' trivially holds for any a, a', r
        (Self(a * G, gai), FactorVerifiersProof(pai, r, gra))
    }
}

impl FactorVerifiersProof {
    #[must_use]
    pub fn verify(&self, verifiers: &FactorVerifiers) -> bool {
        let FactorVerifiers(ga, gai) = verifiers;
        verify_proof(gai, &self.2, &self.0) && self.0.n == self.1 * G && self.1 * ga == self.2
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
    fn verify(&self, original: &ElGamal) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &self.0, &self.1)
    }
    pub fn verify_rerandomized(&self, original: &ElGamal, new: &ElGamal) -> bool {
        self.verify(original) && new.b == self.0 + original.b && new.c == *self.1 + original.c && new.y == original.y
    }
    fn verify_split(_gb: &GroupElement, _gc: &GroupElement, gy: &GroupElement, gr: &GroupElement, p: &Proof) -> bool {
        // slightly different from the others, as we reuse the structure of a standard proof to reconstruct the Rerandomize operation after sending
        verify_proof(gr, gy, p)
    }
}

//// RESHUFFLE

pub type ReshuffleFactor = ScalarNonZero;
pub type ReshuffleFactorVerifiers = FactorVerifiers;

#[derive(Eq, PartialEq, Clone, Copy)]
/// GroupElement is `n*G` if prove_reshuffle with `n` is called.
pub struct ProvedReshuffle(pub Proof, pub Proof);

impl ProvedReshuffle {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s: &ReshuffleFactor, rng: &mut R) -> Self {
        // Reshuffle is normally {s * in.b, s * in.c, in.y};
        // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same s is used, saving a s*G operation)
        let (_gs, pb) = create_proof(&s, &v.b, rng);
        let (_gs, pc) = create_proof(&s, &v.c, rng);
        Self(pb, pc)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, verifiers) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
            y: original.y,
        }
    }
    #[cfg(feature = "elgamal2")]
    fn reconstruct(&self, _original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify(&self, original: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &verifiers.0, &self.0, &self.1)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn verify_reshuffled(&self, original: &ElGamal, new: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> bool {
        self.verify(original, verifiers) && new.b == self.0.n && new.c == self.1.n && new.y == original.y
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, _gy: &GroupElement, gn: &GroupElement, pb: &Proof, pc: &Proof) -> bool {
        verify_proof(gn, gb, pb) && verify_proof(gn, gc, pc)
    }
    #[cfg(feature = "elgamal2")]
    fn verify(&self, original: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &verifiers.0, &self.0, &self.1)
    }
    #[cfg(feature = "elgamal2")]
    pub fn verify_reshuffled(&self, original: &ElGamal, new: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> bool {
        self.verify(original, verifiers) && new.b == self.0.n && new.c == self.1.n
    }
    #[cfg(feature = "elgamal2")]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gn: &GroupElement, pb: &Proof, pc: &Proof) -> bool {
        verify_proof(gn, gb, pb) && verify_proof(gn, gc, pc)
    }
}

pub type RekeyFactor = ScalarNonZero;
pub type RekeyFactorVerifiers = FactorVerifiers;

#[cfg(not(feature = "elgamal2"))]
#[derive(Eq, PartialEq, Clone, Copy)]
/// Second GroupElement is `k*G` if prove_rekey with `k` is called.
pub struct ProvedRekey(pub Proof, pub Proof);

#[cfg(feature = "elgamal2")]
#[derive(Eq, PartialEq, Clone, Copy)]
/// Second GroupElement is `k*G` if prove_rekey with `k` is called.
pub struct ProvedRekey(pub Proof);

impl ProvedRekey {
    #[cfg(not(feature = "elgamal2"))]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, k: &RekeyFactor, rng: &mut R) -> Self {
        // Rekey is normally {in.b/k, in.c, k*in.y};
        let (_, pb) = create_proof(&k.invert(), &v.b, rng);
        let (_, py) = create_proof(k, &v.y, rng);
        Self(pb, py)
    }
    #[cfg(feature = "elgamal2")]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, k: &RekeyFactor, rng: &mut R) -> Self {
        // Rekey is normally {in.b/k, in.c, k*in.y};
        let (_, pb) = create_proof(&k.invert(), &v.b, rng);
        Self(pb)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, verifiers: &RekeyFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, verifiers) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: original.c,
            #[cfg(not(feature = "elgamal2"))]
            y: *self.1,
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify(&self, original: &ElGamal, verifiers: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &verifiers.0, &verifiers.1, &self.0, &self.1)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn verify_reshuffled(&self, original: &ElGamal, new: &ElGamal, verifiers: &RekeyFactorVerifiers) -> bool {
        self.verify(original, verifiers) && new.b == self.0.n && new.c == original.c && new.y == self.1.n
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify_split(gb: &GroupElement, _gc: &GroupElement, gy: &GroupElement, gk: &GroupElement, gki: &GroupElement, pb: &Proof, py: &Proof) -> bool {
        verify_proof(gki, gb, pb) && verify_proof(gk, gy, py)
    }

    #[cfg(feature = "elgamal2")]
    fn verify(&self, original: &ElGamal, verifiers: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &verifiers.0, &verifiers.1, &self.0)
    }
    #[cfg(feature = "elgamal2")]
    pub fn verify_reshuffled(&self, original: &ElGamal, new: &ElGamal, verifiers: &RekeyFactorVerifiers) -> bool {
        self.verify(original, verifiers) && new.b == self.0.n && new.c == original.c
    }
    #[cfg(feature = "elgamal2")]
    fn verify_split(gb: &GroupElement, _gc: &GroupElement, _gk: &GroupElement, gki: &GroupElement, pb: &Proof) -> bool {
        verify_proof(gki, gb, pb)
    }

}

#[cfg(not(feature = "elgamal2"))]
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct ProvedRekeyFromTo(pub Proof, pub Proof, pub Proof, pub Proof);
#[cfg(feature = "elgamal2")]
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct ProvedRekeyFromTo(pub Proof, pub Proof, pub Proof);

impl ProvedRekeyFromTo {
    #[cfg(not(feature = "elgamal2"))]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, k_from: &RekeyFactor, k_to: &RekeyFactor, rng: &mut R) -> Self {
        // RekeyFromTo is normally {k_from * k_to^-1 * in.B, in.c, k_from^-1 * k_to * in.y};
        let k_from_inv = k_from.invert();
        let k = k_from_inv * k_to;
        let (_gki, pb) = create_proof(&k.invert(), &v.b, rng);
        let (_gk, py) = create_proof(&k, &v.y, rng);
        let (_gk_to, pk) = create_proof(k_to, &(k_from_inv * G), rng);
        let (_gki_to, pki) = create_proof(&k_to.invert(), &(k_from * G), rng);
        Self(pb, py, pk, pki)
    }
    #[cfg(feature = "elgamal2")]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, k_from: &RekeyFactor, k_to: &RekeyFactor, rng: &mut R) -> Self {
        // RekeyFromTo is normally {k_from * k_to^-1 * in.B, in.c, k_from^-1 * k_to * in.y};
        let k_from_inv = k_from.invert();
        let k = k_from_inv * k_to;
        let (_gki, pb) = create_proof(&k.invert(), &v.b, rng);
        let (_gk_to, pk) = create_proof(k_to, &(k_from_inv * G), rng);
        let (_gki_to, pki) = create_proof(&k_to.invert(), &(k_from * G), rng);
        Self(pb, pk, pki)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, verifiers_from: &RekeyFactorVerifiers, verifiers_to: &RekeyFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, verifiers_from, verifiers_to) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: original.c,
            #[cfg(not(feature = "elgamal2"))]
            y: *self.1,
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify(&self, original: &ElGamal, verifiers_from: &RekeyFactorVerifiers, verifiers_to: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &verifiers_from.0, &verifiers_from.1, &verifiers_to.0, &verifiers_to.1, &self.0, &self.1, &self.2, &self.3)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn verify_rekey_from_to(&self, original: &ElGamal, new: &ElGamal, verifiers_from: &RekeyFactorVerifiers, verifiers_to: &RekeyFactorVerifiers) -> bool {
        self.verify(original, verifiers_from, verifiers_to) && new.b == self.0.n && new.y == self.1.n && new.c == original.c
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify_split(gb: &GroupElement, _gc: &GroupElement, gy: &GroupElement, gk_from: &GroupElement, gk_from_inv: &GroupElement, gk_to: &GroupElement, gk_to_inv: &GroupElement, pb: &Proof, py: &Proof, pk: &Proof, pki: &Proof) -> bool {
        verify_proof(&pki.n, gb, pb)
            && verify_proof(&pk.n, gy, py)
            && verify_proof(gk_to, gk_from_inv, pk)
            && verify_proof(gk_to_inv, gk_from, pki)
    }
    #[cfg(feature = "elgamal2")]
    fn verify(&self, original: &ElGamal, verifiers_from: &RekeyFactorVerifiers, verifiers_to: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &verifiers_from.0, &verifiers_from.1, &verifiers_to.0, &verifiers_to.1, &self.0, &self.1, &self.2)
    }
    #[cfg(feature = "elgamal2")]
    pub fn verify_rekey_from_to(&self, original: &ElGamal, new: &ElGamal, verifiers_from: &RekeyFactorVerifiers, verifiers_to: &RekeyFactorVerifiers) -> bool {
        self.verify(original, verifiers_from, verifiers_to) && new.b == self.0.n && new.c == original.c
    }
    #[cfg(feature = "elgamal2")]
    fn verify_split(gb: &GroupElement, _gc: &GroupElement, gk_from: &GroupElement, gk_from_inv: &GroupElement, gk_to: &GroupElement, gk_to_inv: &GroupElement, pb: &Proof, pk: &Proof, pki: &Proof) -> bool {
        verify_proof(&pki.n, gb, pb)
            && verify_proof(gk_to, gk_from_inv, pk)
            && verify_proof(gk_to_inv, gk_from, pki)
    }
}

#[derive(Eq, PartialEq, Clone, Copy)]
pub struct ProvedReshuffleFromTo(pub Proof, pub Proof, pub Proof);

impl ProvedReshuffleFromTo {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s_from: &ReshuffleFactor, s_to: &ReshuffleFactor, rng: &mut R) -> Self {
        // ReshuffleFromTo is normally {s_from^-1 * s_to * in.b, s_from^-1 * s_to * in.c, in.y};
        // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same s is used, saving one s*G operation)
        let s = s_from.invert() * s_to;
        let (_gs, pb) = create_proof(&s, &v.b, rng);
        let (_gs, pc) = create_proof(&s, &v.c, rng);
        let (_gs_to, ps) = create_proof(s_to, &(s_from.invert() * G), rng);
        Self(pb, pc, ps)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, verifiers_from, verifiers_to) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
            y: original.y,
        }
    }
    #[cfg(feature = "elgamal2")]
    fn reconstruct(&self, _original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify(&self, original: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &verifiers_from.1, &verifiers_to.0, &self.0, &self.1, &self.2)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn verify_reshuffled_from_to(&self, original: &ElGamal, new: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> bool {
        self.verify(original, verifiers_from, verifiers_to) && new.b == self.0.n && new.c == self.1.n && new.y == original.y
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, _gy: &GroupElement, gs_from_inv: &GroupElement, gs_to: &GroupElement, pb: &Proof, pc: &Proof, ps: &Proof) -> bool {
        // ps is needed as proof that s is constructed as s_from.invert() * s_t
        verify_proof(&ps.n, gb, pb) && verify_proof(&ps.n, gc, pc) && verify_proof(gs_to, gs_from_inv, ps)
    }
    #[cfg(feature = "elgamal2")]
    fn verify(&self, original: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &verifiers_from.1, &verifiers_to.0, &self.0, &self.1, &self.2)
    }
    #[cfg(feature = "elgamal2")]
    pub fn verify_reshuffled_from_to(&self, original: &ElGamal, new: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> bool {
        self.verify(original, verifiers_from, verifiers_to) && new.b == self.0.n && new.c == self.1.n
    }
    #[cfg(feature = "elgamal2")]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gs_from_inv: &GroupElement, gs_to: &GroupElement, pb: &Proof, pc: &Proof, ps: &Proof) -> bool {
        // ps is needed as proof that s is constructed as s_from.invert() * s_t
        verify_proof(&ps.n, gb, pb) && verify_proof(&ps.n, gc, pc) && verify_proof(gs_to, gs_from_inv, ps)
    }
}

#[cfg(not(feature = "elgamal2"))]
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct ProvedRSK(pub Proof, pub Proof, pub Proof, pub Proof);
#[cfg(feature = "elgamal2")]
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct ProvedRSK(pub Proof, pub Proof, pub Proof);

impl ProvedRSK {
    #[cfg(not(feature = "elgamal2"))]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s: &ReshuffleFactor, k: &RekeyFactor, rng: &mut R) -> Self {
        // RSK is normally {s * k^-1 * in.b, s * in.c, k * in.y};
        let ki = k.invert();
        let ski = s * ki;
        let (_gm, pnki) = create_proof(&ki, &(s * G), rng);
        let (_gski, pb) = create_proof(&ski, &v.b, rng);
        let (_gn, pc) = create_proof(&s, &v.c, rng);
        let (_gk, py) = create_proof(k, &v.y, rng);
        Self(pb, pc, py, pnki)
    }
    #[cfg(feature = "elgamal2")]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s: &ReshuffleFactor, k: &RekeyFactor, rng: &mut R) -> Self {
        // RSK is normally {s * k^-1 * in.b, s * in.c, k * in.y};
        let ki = k.invert();
        let ski = s * ki;
        let (_gm, pnki) = create_proof(&ki, &(s * G), rng);
        let (_gski, pb) = create_proof(&ski, &v.b, rng);
        let (_gn, pc) = create_proof(&s, &v.c, rng);
        Self(pb, pc, pnki)
    }


    pub fn verified_reconstruct(&self, original: &ElGamal, reshuffle_verifiers: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, reshuffle_verifiers, rekey_verifiers) {
            Some(self.reconstruct())
        } else {
            None
        }
    }
    fn reconstruct(&self) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
            #[cfg(not(feature = "elgamal2"))]
            y: *self.2,
        }
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify(&self, original: &ElGamal, reshuffle_verifiers: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &reshuffle_verifiers.0, &rekey_verifiers.0, &rekey_verifiers.1, &self.0, &self.1, &self.2, &self.3)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn verify_rskd(&self, original: &ElGamal, new: &ElGamal, reshuffle_verifiers: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        self.verify(original, reshuffle_verifiers, rekey_verifiers) && new.b == self.0.n && new.c == self.1.n && new.y == self.2.n
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gy: &GroupElement, gs: &GroupElement, gk: &GroupElement, gki: &GroupElement, pb: &Proof, pc: &Proof, py: &Proof, pski: &Proof) -> bool {
        verify_proof(&pski.n, gb, pb) && verify_proof(gs, gc, pc) && verify_proof(gk, gy, py) && verify_proof(gki, gs, pski)
    }
    #[cfg(feature = "elgamal2")]
    fn verify(&self, original: &ElGamal, reshuffle_verifiers: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &reshuffle_verifiers.0, &rekey_verifiers.0, &rekey_verifiers.1, &self.0, &self.1, &self.2)
    }
    #[cfg(feature = "elgamal2")]
    pub fn verify_rskd(&self, original: &ElGamal, new: &ElGamal, reshuffle_verifiers: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        self.verify(original, reshuffle_verifiers, rekey_verifiers) && new.b == self.0.n && new.c == self.1.n
    }
    #[cfg(feature = "elgamal2")]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gs: &GroupElement, _gk: &GroupElement, gki: &GroupElement, pb: &Proof, pc: &Proof, pski: &Proof) -> bool {
        verify_proof(&pski.n, gb, pb) && verify_proof(gs, gc, pc) && verify_proof(gki, gs, pski)
    }
}
#[cfg(not(feature = "elgamal2"))]
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct ProvedRSKFromTo(pub Proof, pub Proof, pub Proof, pub Proof, pub Proof, pub Proof, pub Proof);
#[cfg(feature = "elgamal2")]
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct ProvedRSKFromTo(pub Proof, pub Proof, pub Proof, pub Proof, pub Proof, pub Proof);

impl ProvedRSKFromTo {
    #[cfg(not(feature = "elgamal2"))]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s_from: &ReshuffleFactor, s_to: &ReshuffleFactor, k_from: &RekeyFactor, k_to: &RekeyFactor, rng: &mut R) -> Self {
        // RSK is normally {s * k^-1 * in.b, s * in.c, k * in.y};
        let s_from_inv = s_from.invert();
        let k_from_inv = k_from.invert();
        let s = s_from_inv * s_to;
        let k = k_from_inv * k_to;
        let ki = k.invert();
        let ski = s * ki;

        let (_gn_from_inv, ps) = create_proof(&s_from_inv, &(s_to * G), rng);
        let (_gk_to, pk) = create_proof(k_to, &(k_from_inv * G), rng);
        let (_gki_to, pki) = create_proof(&k_to.invert(), &(k_from * G), rng);
        let (_gm, pski) = create_proof(&ki, &ps.n, rng);

        let (_gski, pb) = create_proof(&ski, &v.b, rng);
        let (_gs, pc) = create_proof(&s, &v.c, rng);
        let (_gk, py) = create_proof(&k, &v.y, rng);
        Self(pb, pc, py, pski, ps, pk, pki)
    }
    #[cfg(feature = "elgamal2")]
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, s_from: &ReshuffleFactor, s_to: &ReshuffleFactor, k_from: &RekeyFactor, k_to: &RekeyFactor, rng: &mut R) -> Self {
        // RSK is normally {s * k^-1 * in.b, s * in.c, k * in.y};
        let s_from_inv = s_from.invert();
        let k_from_inv = k_from.invert();
        let s = s_from_inv * s_to;
        let k = k_from_inv * k_to;
        let ki = k.invert();
        let ski = s * ki;

        let (_gn_from_inv, ps) = create_proof(&s_from_inv, &(s_to * G), rng);
        let (_gk_to, pk) = create_proof(k_to, &(k_from_inv * G), rng);
        let (_gki_to, pki) = create_proof(&k_to.invert(), &(k_from * G), rng);
        let (_gm, pski) = create_proof(&ki, &ps.n, rng);

        let (_gski, pb) = create_proof(&ski, &v.b, rng);
        let (_gs, pc) = create_proof(&s, &v.c, rng);
        Self(pb, pc, pski, ps, pk, pki)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers_from: &RekeyFactorVerifiers, rekey_verifiers_to: &RekeyFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, reshuffle_verifiers_from, reshuffle_verifiers_to, rekey_verifiers_from, rekey_verifiers_to){
            Some(self.reconstruct())
        } else {
            None
        }
    }
    fn reconstruct(&self) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
            #[cfg(not(feature = "elgamal2"))]
            y: *self.2,
        }
    }
    // TODO maybe also create an UNSAFE unverified reconstruct? Maybe with a feature flag?
    #[cfg(not(feature = "elgamal2"))]
    fn verify(&self, original: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers_from: &RekeyFactorVerifiers, rekey_verifiers_to: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &reshuffle_verifiers_from.1, &reshuffle_verifiers_to.0, &rekey_verifiers_from.0, &rekey_verifiers_from.1, &rekey_verifiers_to.0, &rekey_verifiers_to.1, &self.0, &self.1, &self.2, &self.3, &self.4, &self.5, &self.6)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn verify_rsk_from_to(&self, original: &ElGamal, new: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers_from: &RekeyFactorVerifiers, rekey_verifiers_to: &RekeyFactorVerifiers) -> bool {
        self.verify(original, reshuffle_verifiers_from, reshuffle_verifiers_to, rekey_verifiers_from, rekey_verifiers_to) && new.b == self.0.n && new.c == self.1.n && new.y == self.2.n
    }
    #[cfg(not(feature = "elgamal2"))]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gy: &GroupElement, gs_from_inv: &GroupElement, gs_to: &GroupElement, gk_from: &GroupElement, gk_from_inv: &GroupElement, gk_to: &GroupElement, gk_to_inv: &GroupElement, pb: &Proof, pc: &Proof, py: &Proof, pski: &Proof, ps: &Proof, pk: &Proof, pki: &Proof) -> bool {
        verify_proof(&pski.n, gb, pb) && verify_proof(&ps.n, gc, pc) && verify_proof(&pk.n, gy, py) && verify_proof(&pki.n, &ps.n, pski) && verify_proof(gs_from_inv, &gs_to, ps) && verify_proof(gk_to, gk_from_inv, pk) && verify_proof(gk_to_inv, gk_from, pki)
    }
    #[cfg(feature = "elgamal2")]
    fn verify(&self, original: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers_from: &RekeyFactorVerifiers, rekey_verifiers_to: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &reshuffle_verifiers_from.1, &reshuffle_verifiers_to.0, &rekey_verifiers_from.0, &rekey_verifiers_from.1, &rekey_verifiers_to.0, &rekey_verifiers_to.1, &self.0, &self.1, &self.2, &self.3, &self.4, &self.5)
    }
    #[cfg(feature = "elgamal2")]
    pub fn verify_rsk_from_to(&self, original: &ElGamal, new: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers_from: &RekeyFactorVerifiers, rekey_verifiers_to: &RekeyFactorVerifiers) -> bool {
        self.verify(original, reshuffle_verifiers_from, reshuffle_verifiers_to, rekey_verifiers_from, rekey_verifiers_to) && new.b == self.0.n && new.c == self.1.n
    }
    #[cfg(feature = "elgamal2")]
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gs_from_inv: &GroupElement, gs_to: &GroupElement, gk_from: &GroupElement, gk_from_inv: &GroupElement, gk_to: &GroupElement, gk_to_inv: &GroupElement, pb: &Proof, pc: &Proof, pski: &Proof, ps: &Proof, pk: &Proof, pki: &Proof) -> bool {
        verify_proof(&pski.n, gb, pb) && verify_proof(&ps.n, gc, pc) && verify_proof(&pki.n, &ps.n, pski) && verify_proof(gs_from_inv, &gs_to, ps) && verify_proof(gk_to, gk_from_inv, pk) && verify_proof(gk_to_inv, gk_from, pki)
    }
}

#[cfg(not(feature = "elgamal2"))]
pub fn prove_rerandomize<R: RngCore + CryptoRng>(v: &ElGamal, r: &ScalarNonZero, rng: &mut R) -> ProvedRerandomize {
    ProvedRerandomize::new(v, r, rng)
}

pub fn prove_reshuffle<R: RngCore + CryptoRng>(v: &ElGamal, s: &ReshuffleFactor, rng: &mut R) -> ProvedReshuffle {
    ProvedReshuffle::new(v, s, rng)
}

pub fn prove_rekey<R: RngCore + CryptoRng>(v: &ElGamal, k: &RekeyFactor, rng: &mut R) -> ProvedRekey {
    ProvedRekey::new(v, k, rng)
}

pub fn prove_reshuffle_from_to<R: RngCore + CryptoRng>(v: &ElGamal, s_from: &ReshuffleFactor, s_to: &ReshuffleFactor, rng: &mut R) -> ProvedReshuffleFromTo {
    ProvedReshuffleFromTo::new(v, s_from, s_to, rng)
}

pub fn prove_rekey_from_to<R: RngCore + CryptoRng>(v: &ElGamal, k_from: &RekeyFactor, k_to: &RekeyFactor, rng: &mut R) -> ProvedRekeyFromTo {
    ProvedRekeyFromTo::new(v, k_from, k_to, rng)
}

pub fn prove_rsk<R: RngCore + CryptoRng>(v: &ElGamal, s: &ReshuffleFactor, k: &RekeyFactor, rng: &mut R) -> ProvedRSK {
    ProvedRSK::new(v, s, k, rng)
}

pub fn prove_rsk_from_to<R: RngCore + CryptoRng>(v: &ElGamal, s_from: &ReshuffleFactor, s_to: &ReshuffleFactor, k_from: &RekeyFactor, k_to: &RekeyFactor, rng: &mut R) -> ProvedRSKFromTo {
    ProvedRSKFromTo::new(v, s_from, s_to, k_from, k_to, rng)
}
