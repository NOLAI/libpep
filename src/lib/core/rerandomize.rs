//! Rerandomization operations for creating binary unlinkable copies of encrypted messages.

use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::data::*;
#[cfg(not(feature = "elgamal3"))]
use crate::core::keys::PublicKey;
use crate::core::transcryption::contexts::RerandomizeFactor;
use rand_core::{CryptoRng, RngCore};

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message.
#[cfg(feature = "elgamal3")]
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted>(encrypted: &E, rng: &mut R) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, &RerandomizeFactor(r))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    rng: &mut R,
) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, public_key, &RerandomizeFactor(r))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message,
/// using a known rerandomization factor.
#[cfg(feature = "elgamal3")]
pub fn rerandomize_known<E: Encrypted>(encrypted: &E, r: &RerandomizeFactor) -> E {
    E::from_value(crate::base::primitives::rerandomize(
        encrypted.value(),
        &r.0,
    ))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message,
/// using a known rerandomization factor.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_known<E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    r: &RerandomizeFactor,
) -> E {
    E::from_value(crate::base::primitives::rerandomize(
        encrypted.value(),
        public_key.value(),
        &r.0,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::data::{decrypt_pseudonym, encrypt_pseudonym, Pseudonym};
    use crate::core::keys::{make_global_keys, make_session_keys};
    use crate::core::transcryption::contexts::EncryptionContext;
    use crate::core::transcryption::secrets::EncryptionSecret;

    #[test]
    fn rerandomize_preserves_plaintext() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test");
        let secret = EncryptionSecret::from(b"secret".to_vec());
        let session = make_session_keys(&global_sk, &context, &secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&pseudonym, &session.pseudonym.public, &mut rng);

        #[cfg(feature = "elgamal3")]
        let rerandomized = rerandomize(&encrypted, &mut rng);
        #[cfg(not(feature = "elgamal3"))]
        let rerandomized = rerandomize(&encrypted, &session.pseudonym.public, &mut rng);

        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt_pseudonym(&rerandomized, &session.pseudonym.secret).expect("decrypt failed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_pseudonym(&rerandomized, &session.pseudonym.secret);
        assert_eq!(pseudonym, decrypted);
    }

    #[test]
    fn rerandomize_changes_ciphertext() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test");
        let secret = EncryptionSecret::from(b"secret".to_vec());
        let session = make_session_keys(&global_sk, &context, &secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&pseudonym, &session.pseudonym.public, &mut rng);

        #[cfg(feature = "elgamal3")]
        let rerandomized = rerandomize(&encrypted, &mut rng);
        #[cfg(not(feature = "elgamal3"))]
        let rerandomized = rerandomize(&encrypted, &session.pseudonym.public, &mut rng);

        // Ciphertext should be different (binary unlinkable)
        assert_ne!(
            encrypted.value().to_bytes(),
            rerandomized.value().to_bytes()
        );
    }

    #[test]
    fn rerandomize_known_deterministic() {
        let mut rng = rand::rng();
        let (_, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test");
        let secret = EncryptionSecret::from(b"secret".to_vec());
        let session = make_session_keys(&global_sk, &context, &secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&pseudonym, &session.pseudonym.public, &mut rng);
        let factor = RerandomizeFactor(ScalarNonZero::random(&mut rng));

        #[cfg(feature = "elgamal3")]
        let r1 = rerandomize_known(&encrypted, &factor);
        #[cfg(not(feature = "elgamal3"))]
        let r1 = rerandomize_known(&encrypted, &session.pseudonym.public, &factor);

        #[cfg(feature = "elgamal3")]
        let r2 = rerandomize_known(&encrypted, &factor);
        #[cfg(not(feature = "elgamal3"))]
        let r2 = rerandomize_known(&encrypted, &session.pseudonym.public, &factor);

        assert_eq!(r1.value().to_bytes(), r2.value().to_bytes());
    }
}
