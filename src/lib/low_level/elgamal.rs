//! ElGamal [encrypt]ion and [decrypt]ion.

use crate::internal::arithmetic::*;
use base64::engine::general_purpose;
use base64::Engine;
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

/// Length of an ElGamal encrypted ciphertext in bytes.
/// Normally, this is 64 bytes, but in the case of the `elgamal3` feature, it is 96 bytes.
#[cfg(not(feature = "elgamal3"))]
pub const ELGAMAL_LENGTH: usize = 64;
#[cfg(feature = "elgamal3")]
pub const ELGAMAL_LENGTH: usize = 96;

/// An ElGamal ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ElGamal {
    pub gb: GroupElement,
    pub gc: GroupElement,
    #[cfg(feature = "elgamal3")]
    pub gy: GroupElement,
}

impl ElGamal {
    /// Decode an ElGamal ciphertext from a byte array.
    pub fn decode(v: &[u8; ELGAMAL_LENGTH]) -> Option<Self> {
        Some(Self {
            gb: GroupElement::decode_from_slice(&v[0..32])?,
            gc: GroupElement::decode_from_slice(&v[32..64])?,
            #[cfg(feature = "elgamal3")]
            gy: GroupElement::decode_from_slice(&v[64..96])?,
        })
    }
    /// Decode an ElGamal ciphertext from a slice of bytes.
    pub fn decode_from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != ELGAMAL_LENGTH {
            None
        } else {
            let mut arr = [0u8; ELGAMAL_LENGTH];
            arr.copy_from_slice(v);
            Self::decode(&arr)
        }
    }

    /// Encode an ElGamal ciphertext as a byte array.
    pub fn encode(&self) -> [u8; ELGAMAL_LENGTH] {
        let mut retval = [0u8; ELGAMAL_LENGTH];
        retval[0..32].clone_from_slice(self.gb.encode().as_ref());
        retval[32..64].clone_from_slice(self.gc.encode().as_ref());
        #[cfg(feature = "elgamal3")]
        retval[64..96].clone_from_slice(self.gy.encode().as_ref());
        retval
    }

    /// Encode an ElGamal ciphertext as a base64 string.
    pub fn encode_as_base64(&self) -> String {
        general_purpose::URL_SAFE.encode(self.encode())
    }
    /// Decode an ElGamal ciphertext from a base64 string.
    pub fn decode_from_base64(s: &str) -> Option<Self> {
        general_purpose::URL_SAFE
            .decode(s)
            .ok()
            .and_then(|v| Self::decode_from_slice(&v))
    }
}

impl Serialize for ElGamal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.encode_as_base64().as_str())
    }
}

impl<'de> Deserialize<'de> for ElGamal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ElGamalVisitor;
        impl Visitor<'_> for ElGamalVisitor {
            type Value = ElGamal;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 encoded string representing an ElGamal ciphertext")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ElGamal::decode_from_base64(v)
                    .ok_or(E::custom(format!("invalid base64 encoded string: {v}")))
            }
        }

        deserializer.deserialize_str(ElGamalVisitor)
    }
}

/// Encrypt message [`GroupElement`] `gm` using public key [`GroupElement`] `gy` to an [`ElGamal`]
/// ciphertext tuple.
/// The randomness is generated using the provided random number generator `rng`.
///
/// Encryption may **not** be done with public key [`GroupElement::identity`], which is checked with an assertion.
pub fn encrypt<R: RngCore + CryptoRng>(
    gm: &GroupElement,
    gy: &GroupElement,
    rng: &mut R,
) -> ElGamal {
    let r = ScalarNonZero::random(rng); // random() should never return a zero scalar
    assert_ne!(gy, &GroupElement::identity()); // we should not encrypt anything with an empty public key, as this will result in plain text sent over the line
    ElGamal {
        gb: r * G,
        gc: gm + r * gy,
        #[cfg(feature = "elgamal3")]
        gy: *gy,
    }
}

/// Decrypt ElGamal ciphertext (encrypted using `y * G`) using secret key [`ScalarNonZero`] `y`.
/// With the `elgamal3` feature, the secret key is checked against the public key used for encryption.
pub fn decrypt(encrypted: &ElGamal, y: &ScalarNonZero) -> GroupElement {
    #[cfg(feature = "elgamal3")]
    assert_eq!(y * G, encrypted.gy); // the secret key should be the same as the public key used to encrypt the message
    encrypted.gc - y * encrypted.gb
}
