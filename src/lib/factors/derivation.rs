//! Derivation of factors from secrets and contexts, and of the info for a transcryption between
//! two contexts.
//!
//! The derivation is generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]; the functions in this module derive ristretto255 factors.
//!
//! Three derivations exist, selected by feature: the default `DeriveFactor` of
//! draft-doesburg-cfrg-coprf, `hmac-derivation` (the derivation of libpep 0.13), and `legacy`
//! (the derivation of the legacy PEP repository). See [`generic`] for the details.

pub mod generic;

use super::secrets::{EncryptionSecret, PseudonymizationSecret};
use super::types::*;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::Ristretto255;
use crate::protocol::Context;

#[cfg(not(feature = "legacy"))]
pub use generic::{LABEL_REKEY_ATTRIBUTE, LABEL_REKEY_PSEUDONYM, LABEL_RESHUFFLE};

/// Derive a pseudonym rekey factor from a secret and a session.
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
    context: &Context,
) -> PseudonymRekeyFactor {
    generic::make_pseudonym_rekey_factor::<Ristretto255>(secret, session, context)
}

/// Derive an attribute rekey factor from a secret and a session.
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
    context: &Context,
) -> AttributeRekeyFactor {
    generic::make_attribute_rekey_factor::<Ristretto255>(secret, session, context)
}

/// Derive a pseudonymisation factor from a secret and a domain.
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
    context: &Context,
) -> ReshuffleFactor {
    generic::make_pseudonymisation_factor::<Ristretto255>(secret, domain, context)
}

#[cfg(all(test, not(feature = "legacy")))]
mod tests {
    use super::generic::make_factor;
    use super::*;
    use crate::factors::secrets::Secret;

    #[test]
    fn factors_are_deterministic_and_identifier_specific() {
        let secret = Secret::from(b"secret".to_vec());
        let ctx = Context::default();
        let a = make_factor::<Ristretto255>(LABEL_REKEY_PSEUDONYM, &secret, b"a", &ctx);
        let b = make_factor::<Ristretto255>(LABEL_REKEY_PSEUDONYM, &secret, b"b", &ctx);
        assert_eq!(
            a,
            make_factor::<Ristretto255>(LABEL_REKEY_PSEUDONYM, &secret, b"a", &ctx)
        );
        assert_ne!(a, b);
        assert_ne!(
            a,
            make_factor::<Ristretto255>(LABEL_REKEY_ATTRIBUTE, &secret, b"a", &ctx)
        );
    }

    #[test]
    fn info_is_the_factor_ratio() {
        let secret = EncryptionSecret::from(b"secret".to_vec());
        let ctx = Context::default();
        let from = EncryptionContext::from("from");
        let to = EncryptionContext::from("to");
        let info = PseudonymRekeyInfo::new(&from, &to, &secret, &ctx);
        let k_from = make_pseudonym_rekey_factor(&secret, &from, &ctx);
        let k_to = make_pseudonym_rekey_factor(&secret, &to, &ctx);
        assert_eq!(k_from.scalar() * info.k.scalar(), k_to.scalar());
        assert_eq!(info.reverse().reverse(), info);
    }
}
