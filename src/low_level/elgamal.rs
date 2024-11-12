use crate::internal::arithmetic::*;
use base64::engine::general_purpose;
use base64::Engine;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[cfg(feature = "elgamal2")]
pub const ELGAMAL_LENGTH: usize = 64;
#[cfg(not(feature = "elgamal2"))]
pub const ELGAMAL_LENGTH: usize = 96;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct ElGamal {
    pub b: GroupElement,
    pub c: GroupElement,
    #[cfg(not(feature = "elgamal2"))]
    pub y: GroupElement,
}

impl ElGamal {
    pub fn decode(v: &[u8; ELGAMAL_LENGTH]) -> Option<Self> {
        Some(Self {
            b: GroupElement::decode_from_slice(&v[0..32])?,
            c: GroupElement::decode_from_slice(&v[32..64])?,
            #[cfg(not(feature = "elgamal2"))]
            y: GroupElement::decode_from_slice(&v[64..96])?,
        })
    }
    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != ELGAMAL_LENGTH {
            None
        } else {
            let mut arr = [0u8; ELGAMAL_LENGTH];
            arr.copy_from_slice(v);
            Self::decode(&arr)
        }
    }

    pub fn encode(&self) -> [u8; ELGAMAL_LENGTH] {
        let mut retval = [0u8; ELGAMAL_LENGTH];
        retval[0..32].clone_from_slice(self.b.encode().as_ref());
        retval[32..64].clone_from_slice(self.c.encode().as_ref());
        #[cfg(not(feature = "elgamal2"))]
        retval[64..96].clone_from_slice(self.y.encode().as_ref());
        retval
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

    pub fn clone(&self) -> Self {
        Self {
            b: self.b,
            c: self.c,
            #[cfg(not(feature = "elgamal2"))]
            y: self.y,
        }
    }
}

/// Encrypt message [GroupElement] `msg` using public key [GroupElement] `public_key` to a ElGamal tuple.
pub fn encrypt<R: RngCore + CryptoRng>(
    msg: &GroupElement,
    public_key: &GroupElement,
    rng: &mut R,
) -> ElGamal {
    let r = ScalarNonZero::random(rng); // random() should never return a zero scalar
    assert_ne!(public_key, &GroupElement::identity()); // we should not encrypt anything with an empty public key, as this will result in plain text sent over the line
    ElGamal {
        b: r * G,
        c: msg + r * public_key,
        #[cfg(not(feature = "elgamal2"))]
        y: *public_key,
    }
}

/// Decrypt ElGamal tuple (encrypted using `secret_key * G`) using secret key [ScalarNonZero] `secret_key`.
pub fn decrypt(s: &ElGamal, secret_key: &ScalarNonZero) -> GroupElement {
    #[cfg(not(feature = "elgamal2"))]
    assert_eq!(secret_key * G, s.y); // the secret key should be the same as the public key used to encrypt the message
    s.c - secret_key * s.b
}
