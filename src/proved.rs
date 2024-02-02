use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::*;
use crate::elgamal::*;
use crate::zkps::*;

pub type PEPFactor = ScalarNonZero;

#[derive(Eq, PartialEq, Clone, Copy)]
pub struct PEPFactorVerifiers(pub GroupElement, pub GroupElement);

pub struct PEPFactorVerifiersProof(Proof, ScalarNonZero, GroupElement);

pub fn generate_pep_factor_verifiers<R: RngCore + CryptoRng>(a: &ScalarNonZero, rng: &mut R) -> (PEPFactorVerifiers, PEPFactorVerifiersProof) {
    let r = ScalarNonZero::random(rng);
    let gra = a * r * G;
    let (gai, pai) = create_proof(&a.invert(), &gra, rng);
    // Checking pki.n == gr proves that a.invert()*a == 1.
    // Assume a'^-1 * (a*r*G) = r*G, then a = a' trivially holds for any a, a', r
    (PEPFactorVerifiers(a * G, gai), PEPFactorVerifiersProof(pai, r, gra))
}

#[must_use]
pub fn verify_pep_factor_verifiers(verifiers: &PEPFactorVerifiers, proof: &PEPFactorVerifiersProof) -> bool {
    let PEPFactorVerifiers(ga, gai) = verifiers;
    let PEPFactorVerifiersProof(pai, r, gra) = proof;
    verify_proof(gai, gra, pai) && pai.n == r * G && r * ga == *gra
}

//// RERANDOMIZE

// We are re-using some variables from the Proof to reconstruct the Rerandomize operation.
// This way, we only need 1 Proof object (which are fairly large)
pub struct ProvedRerandomize(GroupElement, Proof);

impl ProvedRerandomize {
    pub fn new<R: RngCore + CryptoRng>(original: &ElGamal, s: &ScalarNonZero, rng: &mut R) -> Self {
        // Rerandomize is normally {s * G + in.b, s*in.y + in.c, in.y};
        let (gs, p) = create_proof(s, &original.y, rng);
        Self(gs, p)
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
    fn verify_rerandomized(&self, original: &ElGamal, new: &ElGamal) -> bool {
        self.verify(original) && new.b == self.0 + original.b && new.c == *self.1 + original.c && new.y == original.y
    }
    fn verify_split(_gb: &GroupElement, _gc: &GroupElement, gy: &GroupElement, gs: &GroupElement, p: &Proof) -> bool {
        // slightly different than the others, as we reuse the structure of a standard proof to reconstruct the Rerandomize operation after sending
        verify_proof(gs, gy, p)
    }
}
//// RESHUFFLE

pub type ReshuffleFactor = ScalarNonZero;
pub type ReshuffleFactorVerifiers = PEPFactorVerifiers;

/// GroupElement is `n*G` if prove_reshuffle with `n` is called.
pub struct ProvedReshuffle(pub Proof, pub Proof);

impl ProvedReshuffle {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, n: &ReshuffleFactor, rng: &mut R) -> Self {
        // Reshuffle is normally {n * in.b, n * in.c, in.y};
        // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same n is used, saving a n*G operation)
        let (_gn, pb) = create_proof(&n, &v.b, rng);
        let (_gn, pc) = create_proof(&n, &v.c, rng);
        Self(pb, pc)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, verifiers) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
            y: original.y,
        }
    }
    fn verify(&self, original: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &verifiers.0, &self.0, &self.1)
    }
    fn verify_reshuffled(&self, original: &ElGamal, new: &ElGamal, verifiers: &ReshuffleFactorVerifiers) -> bool {
        self.verify(original, verifiers) && new.b == self.0.n && new.c == self.1.n && new.y == original.y
    }
    fn verify_split(gb: &GroupElement, gc: &GroupElement, _gy: &GroupElement, gn: &GroupElement, pb: &Proof, pc: &Proof) -> bool {
        verify_proof(gn, gb, pb) && verify_proof(gn, gc, pc)
    }
}

pub type RekeyFactor = ScalarNonZero;
pub type RekeyFactorVerifiers = PEPFactorVerifiers;

/// Second GroupElement is `k*G` if prove_rekey with `k` is called.
pub struct ProvedRekey(pub Proof, pub Proof);

impl ProvedRekey {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, k: &RekeyFactor, rng: &mut R) -> Self {
        // Rekey is normally {in.b/k, in.c, k*in.y};
        let (_, pb) = create_proof(&k.invert(), &v.b, rng);
        let (_, py) = create_proof(k, &v.y, rng);
        Self(pb, py)
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
            y: *self.1,
        }
    }
    fn verify(&self, original: &ElGamal, verifiers: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &verifiers.0, &verifiers.1, &self.0, &self.1)
    }
    fn verify_reshuffled(&self, original: &ElGamal, new: &ElGamal, verifiers: &RekeyFactorVerifiers) -> bool {
        self.verify(original, verifiers) && new.b == self.0.n && new.c == original.c && new.y == self.1.n
    }
    fn verify_split(gb: &GroupElement, _gc: &GroupElement, gy: &GroupElement, gk: &GroupElement, gki: &GroupElement, pb: &Proof, py: &Proof) -> bool {
        verify_proof(gki, gb, pb) && verify_proof(gk, gy, py)
    }
}

pub struct ProvedReshuffleFromTo(pub Proof, pub Proof, pub Proof);

impl ProvedReshuffleFromTo {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, n_from: &ReshuffleFactor, n_to: &ReshuffleFactor, rng: &mut R) -> Self {
        // Reshuffle is normally {n_from^-1 * n_to * in.b, n_from^-1 * n_to * in.c, in.y};
        // NOTE: can be optimised a bit, by fusing the two CreateProofs (because same n is used, saving a n*G operation)
        let n = n_from.invert() * n_to;
        let (_gn, pb) = create_proof(&n, &v.b, rng);
        let (_gn, pc) = create_proof(&n, &v.c, rng);
        let (_gn_to, pn) = create_proof(n_to, &(n_from.invert() * G), rng);
        Self(pb, pc, pn)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, verifiers_from, verifiers_to) {
            Some(self.reconstruct(original))
        } else {
            None
        }
    }
    fn reconstruct(&self, original: &ElGamal) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
            y: original.y,
        }
    }
    fn verify(&self, original: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &verifiers_from.1, &verifiers_to.0, &self.0, &self.1, &self.2)
    }
    fn verify_reshuffled_from_to(&self, original: &ElGamal, new: &ElGamal, verifiers_from: &ReshuffleFactorVerifiers, verifiers_to: &ReshuffleFactorVerifiers) -> bool {
        self.verify(original, verifiers_from, verifiers_to) && new.b == self.0.n && new.c == self.1.n && new.y == original.y
    }
    fn verify_split(gb: &GroupElement, gc: &GroupElement, _gy: &GroupElement, gn_from_inv: &GroupElement, gn_to: &GroupElement, pb: &Proof, pc: &Proof, pn: &Proof) -> bool {
        // pn is needed as proof that n is constructed as n_from.invert() * n_t
        verify_proof(&pn.n, gb, pb) && verify_proof(&pn.n, gc, pc) && verify_proof(gn_to, gn_from_inv, pn)
    }
}

pub struct ProvedRSK(pub Proof, pub Proof, pub Proof, pub Proof);

impl ProvedRSK {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, n: &ReshuffleFactor, k: &RekeyFactor, rng: &mut R) -> Self {
        // RSK is normally {n * k^-1 * in.b, n * in.c, k * in.y};
        let ki = k.invert();
        let nki = n * ki;
        let (_gm, pnki) = create_proof(&ki, &(n * G), rng);
        let (_gnki, pb) = create_proof(&nki, &v.b, rng);
        let (_gn, pc) = create_proof(&n, &v.c, rng);
        let (_gk, py) = create_proof(k, &v.y, rng);
        Self(pb, pc, py, pnki)
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
            y: *self.2,
        }
    }
    fn verify(&self, original: &ElGamal, reshuffle_verifiers: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &reshuffle_verifiers.0, &rekey_verifiers.0, &rekey_verifiers.1, &self.0, &self.1, &self.2, &self.3)
    }
    fn verify_rskd(&self, original: &ElGamal, new: &ElGamal, reshuffle_verifiers: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        self.verify(original, reshuffle_verifiers, rekey_verifiers) && new.b == self.0.n && new.c == self.1.n && new.y == self.2.n
    }
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gy: &GroupElement, gn: &GroupElement, gk: &GroupElement, gki: &GroupElement, pb: &Proof, pc: &Proof, py: &Proof, pnki: &Proof) -> bool {
        verify_proof(&pnki.n, gb, pb) && verify_proof(gn, gc, pc) && verify_proof(gk, gy, py) && verify_proof(gki, gn, pnki)
    }
}

pub struct ProvedRSKFromTo(pub Proof, pub Proof, pub Proof, pub Proof, pub Proof);

impl ProvedRSKFromTo {
    pub fn new<R: RngCore + CryptoRng>(v: &ElGamal, n_from: &ReshuffleFactor, n_to: &ReshuffleFactor, k: &RekeyFactor, rng: &mut R) -> Self {
        // RSK is normally {n * k^-1 * in.b, n * in.c, k * in.y};
        let n_from_inv = n_from.invert();
        let n = n_from_inv * n_to;
        let ki = k.invert();
        let nki = n * ki;
        let (_gn_from_inv, pn) = create_proof(&n_from_inv, &(n_to * G), rng);
        let (_gm, pnki) = create_proof(&ki, &pn.n, rng);
        let (_gnki, pb) = create_proof(&nki, &v.b, rng);
        let (_gn, pc) = create_proof(&n, &v.c, rng);
        let (_gk, py) = create_proof(k, &v.y, rng);
        Self(pb, pc, py, pnki, pn)
    }
    pub fn verified_reconstruct(&self, original: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> Option<ElGamal> {
        if self.verify(original, reshuffle_verifiers_from, reshuffle_verifiers_to, rekey_verifiers) {
            Some(self.reconstruct())
        } else {
            None
        }
    }
    fn reconstruct(&self) -> ElGamal {
        ElGamal {
            b: *self.0,
            c: *self.1,
            y: *self.2,
        }
    }
    fn verify(&self, original: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        Self::verify_split(&original.b, &original.c, &original.y, &reshuffle_verifiers_from.1, &reshuffle_verifiers_to.0, &rekey_verifiers.0, &rekey_verifiers.1, &self.0, &self.1, &self.2, &self.3, &self.4)
    }
    fn verify_rskd_from_to(&self, original: &ElGamal, new: &ElGamal, reshuffle_verifiers_from: &ReshuffleFactorVerifiers, reshuffle_verifiers_to: &ReshuffleFactorVerifiers, rekey_verifiers: &RekeyFactorVerifiers) -> bool {
        self.verify(original, reshuffle_verifiers_from, reshuffle_verifiers_to, rekey_verifiers) && new.b == self.0.n && new.c == self.1.n && new.y == self.2.n
    }
    fn verify_split(gb: &GroupElement, gc: &GroupElement, gy: &GroupElement, gn_from_inv: &GroupElement, gn_to: &GroupElement, gk: &GroupElement, gki: &GroupElement, pb: &Proof, pc: &Proof, py: &Proof, pnki: &Proof, pn: &Proof) -> bool {
        verify_proof(&pnki.n, gb, pb) && verify_proof(&pn.n, gc, pc) && verify_proof(gk, gy, py) && verify_proof(gki, &pn.n, pnki) && verify_proof(gn_from_inv, &gn_to, pn)
    }
}

pub fn prove_rerandomize<R: RngCore + CryptoRng>(v: &ElGamal, s: &ScalarNonZero, rng: &mut R) -> ProvedRerandomize {
    ProvedRerandomize::new(v, s, rng)
}

pub fn prove_reshuffle<R: RngCore + CryptoRng>(v: &ElGamal, n: &ReshuffleFactor, rng: &mut R) -> ProvedReshuffle {
    ProvedReshuffle::new(v, n, rng)
}

pub fn prove_rekey<R: RngCore + CryptoRng>(v: &ElGamal, k: &RekeyFactor, rng: &mut R) -> ProvedRekey {
    ProvedRekey::new(v, k, rng)
}

pub fn prove_reshuffle_from_to<R: RngCore + CryptoRng>(v: &ElGamal, n_from: &ReshuffleFactor, n_to: &ReshuffleFactor, rng: &mut R) -> ProvedReshuffleFromTo {
    ProvedReshuffleFromTo::new(v, n_from, n_to, rng)
}

pub fn prove_rsk<R: RngCore + CryptoRng>(v: &ElGamal, n: &ReshuffleFactor, k: &RekeyFactor, rng: &mut R) -> ProvedRSK {
    ProvedRSK::new(v, n, k, rng)
}

pub fn prove_rsk_from_to<R: RngCore + CryptoRng>(v: &ElGamal, n_from: &ReshuffleFactor, n_to: &ReshuffleFactor, k: &RekeyFactor, rng: &mut R) -> ProvedRSKFromTo {
    ProvedRSKFromTo::new(v, n_from, n_to, k, rng)
}
