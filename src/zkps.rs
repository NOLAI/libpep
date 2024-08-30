use std::ops::Deref;
use rand_core::{CryptoRng, RngCore};
use sha2::{Sha512, Digest};
use crate::arithmetic::*;

// Offline Schnorr proof using Fiat-Shamir transform.
// Proof that given a GroupElement `m` and a scalar `a`,
// member `n` is equal to `a*m`. This can be verified using
// this struct, the original `m` and `a*G`, so that the original
// scalar `a` remains secret.
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct Proof {
    pub n: GroupElement,
    pub c1: GroupElement,
    pub c2: GroupElement,
    pub s: ScalarCanBeZero,
}

impl Deref for Proof {
    type Target = GroupElement;

    fn deref(&self) -> &Self::Target {
        &self.n
    }
}

// returns <A=a*G, Proof with a value N = a*M>
pub fn create_proof<R: RngCore + CryptoRng>(a: &ScalarNonZero, gm: &GroupElement, rng: &mut R) -> (GroupElement, Proof) {
    let r = ScalarNonZero::random(rng);

    let ga = a * G;
    let gn = a * gm;
    let gc1 = r * G;
    let gc2 = r * gm;

    let mut hasher = Sha512::default();
    hasher.update(ga.encode());
    hasher.update(gm.encode());
    hasher.update(gn.0.compress().as_bytes());
    hasher.update(gc1.0.compress().as_bytes());
    hasher.update(gc2.0.compress().as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::decode_from_hash(&bytes);
    let s = ScalarCanBeZero::from(a * e) + ScalarCanBeZero::from(r);
    (ga, Proof { n: gn, c1: gc1, c2: gc2, s })
}

#[must_use]
pub fn verify_proof_split(ga: &GroupElement, gm: &GroupElement, gn: &GroupElement, gc1: &GroupElement, gc2: &GroupElement, s: &ScalarCanBeZero) -> bool {
    let mut hasher = Sha512::default();
    hasher.update(ga.0.compress().as_bytes());
    hasher.update(gm.0.compress().as_bytes());
    hasher.update(gn.0.compress().as_bytes());
    hasher.update(gc1.0.compress().as_bytes());
    hasher.update(gc2.0.compress().as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::decode_from_hash(&bytes);
    // FIXME: speed up with https://docs.rs/curve25519-dalek/latest/curve25519_dalek/traits/trait.VartimeMultiscalarMul.html
    // FIXME: check if a faster non-constant time equality can be used
    s * G == e * ga + gc1 && s * gm == e * gn + gc2
    // (a*e + r)*G = e*a*G + r*G
    // (a*e + r)*gm == e*a*gm + r*gm
}

#[must_use]
pub fn verify_proof(ga: &GroupElement, gm: &GroupElement, p: &Proof) -> bool {
    verify_proof_split(ga, gm, &p.n, &p.c1, &p.c2, &p.s)
}

//// SIGNATURES

type Signature = Proof;

pub fn sign<R: RngCore + CryptoRng>(message: &GroupElement, secret_key: &ScalarNonZero, rng: &mut R) -> Signature {
    create_proof(secret_key, message, rng).1
}
#[must_use]
pub fn verify(message: &GroupElement, p: &Signature, public_key: &GroupElement) -> bool {
    verify_proof(public_key, message, p)
}

// NON-RANDOMIZED SIGNATURES
// Signatures that do not make use of a random nonce, and are therefore do not make the data linkable based on the signature.
// using Fiat-Shamir transform
pub fn create_proof_unlinkable(a: &ScalarNonZero, gm: &GroupElement) -> (GroupElement, Proof) {
    let mut hasher = Sha512::default();
    hasher.update(gm.encode());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let r = ScalarNonZero::decode_from_hash(&bytes);

    let ga = a * G;
    let gn = a * gm;
    let gc1 = r * G;
    let gc2 = r * gm;

    let mut hasher = Sha512::default();
    hasher.update(ga.encode());
    hasher.update(gm.encode());
    hasher.update(gn.0.compress().as_bytes());
    hasher.update(gc1.0.compress().as_bytes());
    hasher.update(gc2.0.compress().as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::decode_from_hash(&bytes);
    let s = ScalarCanBeZero::from(a * e) + ScalarCanBeZero::from(r);
    (ga, Proof { n: gn, c1: gc1, c2: gc2, s })
}

pub fn sign_unlinkable(message: &GroupElement, secret_key: &ScalarNonZero) -> Signature {
    create_proof_unlinkable(secret_key, message).1
}

