//! ElGamal [encrypt]ion and [decrypt]ion, the underlying group [arithmetic], and the low-level
//! (n)-PEP [primitives] that operate on ElGamal ciphertexts.
//!
//! This module is intended for non-standard use cases where the individual (n)-PEP primitives
//! are needed.
//! For most use cases, the [high-level](crate::transcryptor) API should be used, which provides
//! a more user-friendly and safer interface.
//!
//! The ciphertext and the encryption functions are generic over the [`Group`](arithmetic::Group) in [`generic`];
//! this module instantiates them for ristretto255.

pub mod arithmetic;
pub mod generic;
pub mod primitives;

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use crate::elgamal::arithmetic::Ristretto255;
use rand_core::{CryptoRng, Rng};

/// An ElGamal ciphertext over ristretto255.
pub type ElGamal = generic::ElGamal<Ristretto255>;

/// Length of an ElGamal encrypted ciphertext in bytes.
/// Normally, this is 64 bytes, but in the case of the `elgamal3` feature, it is 96 bytes.
pub const ELGAMAL_LENGTH: usize = ElGamal::LENGTH;

/// Encrypt message [`GroupElement`] `gm` using public key [`GroupElement`] `gy` to an [`ElGamal`]
/// ciphertext tuple.
/// The randomness is generated using the provided random number generator `rng`.
///
/// Encryption may **not** be done with public key [`GroupElement::identity`], which is checked with an assertion.
pub fn encrypt<R: Rng + CryptoRng>(gm: &GroupElement, gy: &GroupElement, rng: &mut R) -> ElGamal {
    generic::encrypt::<Ristretto255, R>(gm, gy, rng)
}

/// Decrypt ElGamal ciphertext (encrypted using `y * G`) using secret key [`ScalarNonZero`] `y`.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match the public key used for encryption.
#[cfg(feature = "elgamal3")]
pub fn decrypt(encrypted: &ElGamal, y: &ScalarNonZero) -> Option<GroupElement> {
    generic::decrypt(encrypted, y)
}

/// Decrypt ElGamal ciphertext (encrypted using `y * G`) using secret key [`ScalarNonZero`] `y`.
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt(encrypted: &ElGamal, y: &ScalarNonZero) -> GroupElement {
    generic::decrypt(encrypted, y)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::group_elements::G;

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
    fn bytes_roundtrip() {
        let mut rng = rand::rng();
        let message = GroupElement::random(&mut rng);
        let public_key = GroupElement::random(&mut rng);
        let encrypted = encrypt(&message, &public_key, &mut rng);

        let bytes = encrypted.to_bytes();
        assert_eq!(bytes.len(), ELGAMAL_LENGTH);
        assert_eq!(ElGamal::from_slice(&bytes), Some(encrypted));
        assert_eq!(ElGamal::from_slice(&bytes[1..]), None);
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
