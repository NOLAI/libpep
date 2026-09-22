//! Derivation of factors from secrets and contexts, and of the info for a transcryption between
//! two contexts.
//!
//! The derivation is generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]; the functions in this module derive ristretto255 factors.

pub mod generic;

use super::secrets::{EncryptionSecret, PseudonymizationSecret};
use super::types::*;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::Ristretto255;

/// Derive a pseudonym rekey factor from a secret and a context.
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> PseudonymRekeyFactor {
    generic::make_pseudonym_rekey_factor::<Ristretto255>(secret, context)
}

/// Derive an attribute rekey factor from a secret and a context.
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> AttributeRekeyFactor {
    generic::make_attribute_rekey_factor::<Ristretto255>(secret, context)
}

/// Derive a pseudonymisation factor from a secret and a context.
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    generic::make_pseudonymisation_factor::<Ristretto255>(secret, domain)
}

#[cfg(all(test, not(feature = "legacy")))]
mod tests {
    use super::generic::{make_factor, scalar_from_hash_excluding_zero_and_one};
    use super::*;
    use crate::factors::secrets::Secret;

    #[test]
    fn degenerate_scalars_are_rejected() {
        let zero = [0u8; 64];
        assert!(scalar_from_hash_excluding_zero_and_one::<Ristretto255>(&zero).is_none());
        let mut one = [0u8; 64];
        one[0] = 1;
        assert!(scalar_from_hash_excluding_zero_and_one::<Ristretto255>(&one).is_none());
        let mut two = [0u8; 64];
        two[0] = 2;
        assert!(scalar_from_hash_excluding_zero_and_one::<Ristretto255>(&two).is_some());
    }

    #[test]
    fn factors_are_deterministic_and_context_specific() {
        let secret = Secret::from(b"secret".to_vec());
        let a = make_factor::<Ristretto255>(1, &secret, &"a".to_string());
        let b = make_factor::<Ristretto255>(1, &secret, &"b".to_string());
        assert_eq!(a, make_factor::<Ristretto255>(1, &secret, &"a".to_string()));
        assert_ne!(a, b);
        assert_ne!(a, make_factor::<Ristretto255>(2, &secret, &"a".to_string()));
    }

    #[test]
    fn info_is_the_factor_ratio() {
        let secret = EncryptionSecret::from(b"secret".to_vec());
        let from = EncryptionContext::from("from");
        let to = EncryptionContext::from("to");
        let info = PseudonymRekeyInfo::new(&from, &to, &secret);
        let k_from = make_pseudonym_rekey_factor(&secret, &from);
        let k_to = make_pseudonym_rekey_factor(&secret, &to);
        assert_eq!(k_from.scalar() * info.k.scalar(), k_to.scalar());
        assert_eq!(info.reverse().reverse(), info);
    }
}
