use crate::arithmetic::*;
use derive_more::Deref;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::fmt::Formatter;

use base64::engine::general_purpose;
use base64::Engine;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Offline Schnorr proof using Fiat-Shamir transform.
// Proof that given a GroupElement `m` and a scalar `a`,
// member `n` is equal to `a*m`. This can be verified using
// this struct, the original `m` and `a*G`, so that the original
// scalar `a` remains secret.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Deref)]
pub struct Proof {
    #[deref]
    pub n: GroupElement,
    pub c1: GroupElement,
    pub c2: GroupElement,
    pub s: ScalarCanBeZero,
}

impl Proof {
    pub fn encode(&self) -> [u8; 128] {
        let mut retval = [0u8; 128];
        retval[0..32].clone_from_slice(self.n.encode().as_ref());
        retval[32..64].clone_from_slice(self.c1.encode().as_ref());
        retval[64..96].clone_from_slice(self.c2.encode().as_ref());
        retval[96..128].clone_from_slice(self.s.encode().as_ref());
        retval
    }

    pub fn decode(v: &[u8; 128]) -> Option<Self> {
        Some(Self {
            n: GroupElement::decode_from_slice(&v[0..32])?,
            c1: GroupElement::decode_from_slice(&v[32..64])?,
            c2: GroupElement::decode_from_slice(&v[64..96])?,
            s: ScalarCanBeZero::decode_from_slice(&v[96..128])?,
        })
    }

    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != 128 {
            None
        } else {
            let mut arr = [0u8; 128];
            arr.copy_from_slice(v);
            Self::decode(&arr)
        }
    }

    pub fn encode_to_base64(&self) -> String {
        general_purpose::URL_SAFE.encode(&self.encode())
    }
    pub fn decode_from_base64(s: &str) -> Option<Self> {
        general_purpose::URL_SAFE
            .decode(s)
            .ok()
            .and_then(|v| Self::decode_from_slice(&v))
    }
}

impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode_to_base64().as_str())
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProofVisitor;
        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = Proof;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 encoded string representing a Proof")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Proof::decode_from_base64(&v)
                    .ok_or(E::custom(format!("invalid base64 encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(ProofVisitor)
    }
}

// returns <A=a*G, Proof with a value N = a*M>
pub fn create_proof<R: RngCore + CryptoRng>(
    a: &ScalarNonZero,
    gm: &GroupElement,
    rng: &mut R,
) -> (GroupElement, Proof) {
    let r = ScalarNonZero::random(rng);

    let ga = a * G;
    let gn = a * gm;
    let gc1 = r * G;
    let gc2 = r * gm;

    let mut hasher = Sha512::default();
    hasher.update(ga.encode());
    hasher.update(gm.encode());
    hasher.update(gn.encode());
    hasher.update(gc1.encode());
    hasher.update(gc2.encode());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::decode_from_hash(&bytes);
    let s = ScalarCanBeZero::from(a * e) + ScalarCanBeZero::from(r);
    (
        ga,
        Proof {
            n: gn,
            c1: gc1,
            c2: gc2,
            s,
        },
    )
}

#[must_use]
pub fn verify_proof_split(
    ga: &GroupElement,
    gm: &GroupElement,
    gn: &GroupElement,
    gc1: &GroupElement,
    gc2: &GroupElement,
    s: &ScalarCanBeZero,
) -> bool {
    let mut hasher = Sha512::default();
    hasher.update(ga.encode());
    hasher.update(gm.encode());
    hasher.update(gn.encode());
    hasher.update(gc1.encode());
    hasher.update(gc2.encode());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::decode_from_hash(&bytes);
    // FIXME speed up with https://docs.rs/curve25519-dalek/latest/curve25519_dalek/traits/trait.VartimeMultiscalarMul.html
    // FIXME check if a faster non-constant time equality can be used
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

pub fn sign<R: RngCore + CryptoRng>(
    message: &GroupElement,
    secret_key: &ScalarNonZero,
    rng: &mut R,
) -> Signature {
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
    hasher.update(gn.encode());
    hasher.update(gc1.encode());
    hasher.update(gc2.encode());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    let e = ScalarNonZero::decode_from_hash(&bytes);
    let s = ScalarCanBeZero::from(a * e) + ScalarCanBeZero::from(r);
    (
        ga,
        Proof {
            n: gn,
            c1: gc1,
            c2: gc2,
            s,
        },
    )
}

pub fn sign_unlinkable(message: &GroupElement, secret_key: &ScalarNonZero) -> Signature {
    create_proof_unlinkable(secret_key, message).1
}
