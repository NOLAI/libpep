//! Verifiable factor derivation using Carter-Wegman universal hashing.
//!
//! Factor commitments are publicly computable from master public keys, so
//! the transcryptor does not need to publish a per-domain / per-session
//! commitment for every factor it uses — the verifier reconstructs them
//! from a single master public-key pair plus the domain / session identifier.
//!
//! # Construction
//!
//! For a domain `d`, the reshuffling factor is derived as:
//! ```text
//! s_d = x₁ · H₁(d) + x₂ · H₂(d)
//! ```
//! and its forward commitment as:
//! ```text
//! S_d = s_d · G = H₁(d) · X₁ + H₂(d) · X₂
//! ```
//! where `X₁ = x₁·G` and `X₂ = x₂·G` are the master public keys.
//!

//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`MasterPseudonymizationSecret`](generic::MasterPseudonymizationSecret) over ristretto255.
pub type MasterPseudonymizationSecret = generic::MasterPseudonymizationSecret<Ristretto255>;
/// The [`MasterPseudonymizationPublicKey`](generic::MasterPseudonymizationPublicKey) over
/// ristretto255.
pub type MasterPseudonymizationPublicKey = generic::MasterPseudonymizationPublicKey<Ristretto255>;
/// The [`MasterRekeyingSecret`](generic::MasterRekeyingSecret) over ristretto255.
pub type MasterRekeyingSecret = generic::MasterRekeyingSecret<Ristretto255>;
/// The [`MasterRekeyingPublicKey`](generic::MasterRekeyingPublicKey) over ristretto255.
pub type MasterRekeyingPublicKey = generic::MasterRekeyingPublicKey<Ristretto255>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::contexts::{EncryptionContext, PseudonymizationDomain};
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::arithmetic::Ristretto255;

    #[test]
    fn test_master_pseudonymization_key_derivation() {
        let mut rng = rand::rng();
        let secret = MasterPseudonymizationSecret::random(&mut rng);
        let public = secret.public_key();
        let domain = PseudonymizationDomain::from("test_domain");
        let factor = secret.derive_reshuffle_factor(&domain);
        let commitment = public.compute_reshuffle_commitment(&domain);
        // The commitment computed from the public key must equal s_d·G.
        assert_eq!(commitment, factor * G);
    }

    #[test]
    fn test_master_rekeying_key_derivation() {
        let mut rng = rand::rng();
        let secret = MasterRekeyingSecret::random(&mut rng);
        let public = secret.public_key();
        let context = EncryptionContext::from("test_session");
        let factor = secret.derive_pseudonym_rekey_factor(&context);
        let commitment = public.compute_pseudonym_rekey_commitment(&context);
        assert_eq!(commitment, factor * G);
    }

    #[test]
    fn test_hash_functions_independence() {
        let input = b"test_input";
        let h1 = generic::hash_to_scalar_1::<Ristretto255>(b"type", input);
        let h2 = generic::hash_to_scalar_2::<Ristretto255>(b"type", input);
        assert_ne!(h1, h2);
    }
}
