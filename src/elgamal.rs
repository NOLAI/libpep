use rand_core::{CryptoRng, RngCore};
use crate::arithmetic::*;
#[derive(Debug, Eq, PartialEq)]
pub struct ElGamal {
    pub b: GroupElement,
    pub c: GroupElement,
    pub y: GroupElement,
}
impl ElGamal {
    pub fn encode(&self) -> [u8; 96] {
        let mut retval = [0u8; 96];
        retval[0..32].clone_from_slice(self.b.0.compress().as_bytes());
        retval[32..64].clone_from_slice(self.c.0.compress().as_bytes());
        retval[64..96].clone_from_slice(self.y.0.compress().as_bytes());
        retval
    }

    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() != 96 {
            None
        } else {
            Some(Self {
                b: GroupElement::decode_from_slice(&v[0..32])?,
                c: GroupElement::decode_from_slice(&v[32..64])?,
                y: GroupElement::decode_from_slice(&v[64..96])?,
            })
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            b: self.b,
            c: self.c,
            y: self.y,
        }
    }
}

/// Encrypt message [GroupElement] `msg` using public key [GroupElement] `public_key` to a ElGamal tuple.
pub fn encrypt<R: RngCore + CryptoRng>(msg: &GroupElement, public_key: &GroupElement, rng: &mut R) -> ElGamal {
    let r = ScalarNonZero::random(rng); // random() should never return a zero scalar
    debug_assert!(public_key != &GroupElement::identity()); // we should not encrypt anything with an empty public key, as this will result in plain text send over the line
    ElGamal {
        b: r * G,
        c: msg + r * public_key,
        y: *public_key,
    }
}


/// Encrypt message [GroupElement] `msg` using randomized public key [GroupElement] `public_key` and the randomizer [GroupElement] `randomizer_g` to a ElGamal tuple. A randomized public key can be computed from a [GroupElement] public key `pk` by `randomizer*pk` using a random [ScalarNonZero] randomizer. The `randomizer` can be converted to the necessary [GroupElement] argument by doing `randomizer*G`.
pub fn encrypt_using_randomizer<R: RngCore + CryptoRng>(msg: &GroupElement, public_key: &GroupElement, randomizer_g: &GroupElement, rng: &mut R) -> ElGamal {
    debug_assert!(public_key != &GroupElement::identity()); // we should not encrypt anything with an empty public key, as this will result in plain text send over the line
    let r = ScalarNonZero::random(rng); // random() should never return a zero scalar
    ElGamal {
        b: r * G,
        c: msg + r * public_key + r * randomizer_g,
        y: *public_key,
    }
}

/// Decrypt ElGamal tuple (encrypted using `secret_key * G`) using secret key [ScalarNonZero] `secret_key`.
pub fn decrypt(s: &ElGamal, secret_key: &ScalarNonZero) -> GroupElement {
    s.c - secret_key * s.b
}
