//! ElGamal [encrypt]ion and [decrypt]ion.

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use base64::engine::general_purpose;
use base64::Engine;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::de::{Error, Visitor};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
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
    /// Create from a byte array.
    pub fn from_bytes(v: &[u8; ELGAMAL_LENGTH]) -> Option<Self> {
        Some(Self {
            gb: GroupElement::from_slice(&v[0..32])?,
            gc: GroupElement::from_slice(&v[32..64])?,
            #[cfg(feature = "elgamal3")]
            gy: GroupElement::from_slice(&v[64..96])?,
        })
    }

    /// Create from a slice of bytes.
    pub fn from_slice(v: &[u8]) -> Option<Self> {
        if v.len() != ELGAMAL_LENGTH {
            None
        } else {
            let mut arr = [0u8; ELGAMAL_LENGTH];
            arr.copy_from_slice(v);
            Self::from_bytes(&arr)
        }
    }

    /// Convert to a byte array.
    pub fn to_bytes(&self) -> [u8; ELGAMAL_LENGTH] {
        let mut retval = [0u8; ELGAMAL_LENGTH];
        retval[0..32].clone_from_slice(self.gb.to_bytes().as_ref());
        retval[32..64].clone_from_slice(self.gc.to_bytes().as_ref());
        #[cfg(feature = "elgamal3")]
        retval[64..96].clone_from_slice(self.gy.to_bytes().as_ref());
        retval
    }

    /// Convert to a base64 string.
    pub fn to_base64(&self) -> String {
        general_purpose::URL_SAFE.encode(self.to_bytes())
    }

    /// Create from a base64 string.
    pub fn from_base64(s: &str) -> Option<Self> {
        general_purpose::URL_SAFE
            .decode(s)
            .ok()
            .and_then(|v| Self::from_slice(&v))
    }
}

#[cfg(feature = "serde")]
impl Serialize for ElGamal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_base64().as_str())
    }
}

#[cfg(feature = "serde")]
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
                ElGamal::from_base64(v)
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
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match the public key used for encryption.
#[cfg(feature = "elgamal3")]
pub fn decrypt(encrypted: &ElGamal, y: &ScalarNonZero) -> Option<GroupElement> {
    if y * G != encrypted.gy {
        return None;
    }
    Some(encrypted.gc - y * encrypted.gb)
}

/// Decrypt ElGamal ciphertext (encrypted using `y * G`) using secret key [`ScalarNonZero`] `y`.
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt(encrypted: &ElGamal, y: &ScalarNonZero) -> GroupElement {
    encrypted.gc - y * encrypted.gb
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = rand::rng();
        let secret_key = ScalarNonZero::random(&mut rng);
        let public_key = secret_key * G;
        let message = GroupElement::random(&mut rng);

        let encrypted = encrypt(&message, &public_key, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &secret_key).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &secret_key);

        assert_eq!(message, decrypted);
    }

    #[test]
    fn base64_roundtrip() {
        let mut rng = rand::rng();
        let message = GroupElement::random(&mut rng);
        let public_key = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);

        let encoded = encrypted.to_base64();
        let decoded = ElGamal::from_base64(&encoded).expect("base64 decoding should succeed");

        assert_eq!(encrypted, decoded);
    }

    #[test]
    fn known_base64_decoding() {
        #[cfg(feature = "elgamal3")]
        let base64 = "NESP1FCKkF7nWbqM9cvuUEUPgHaF8qnLeW9RLe_5FCMs-daoTGSyJKa5HRKxk0jFMHVuZ77pJMacNLmtRnlkZEpkKEPWnLzh_s8ievM3gTqeBYm20E23K6hExSxMOw8D";
        #[cfg(not(feature = "elgamal3"))]
        let base64 =
            "xGOnBZzbSrvKUQYBtww0vi8jZWzN9qkrm5OnI2pnEFJu4DkZP2jLLGT-yWa_qnkC_ScCwQwcQtZk_z_z7s_gVQ==";

        let decoded = ElGamal::from_base64(base64).expect("decoding should succeed");
        let re_encoded = decoded.to_base64();

        assert_eq!(base64, re_encoded);
    }
}
