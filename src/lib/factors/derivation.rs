//! Derivation of factors from secrets and contexts, and of the info for a transcryption between
//! two contexts.
//!
//! The derivation is generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]; the functions in this module derive ristretto255 factors.
//!
//! Three derivations exist, selected by feature:
//!
//! - The default is `DeriveFactor` of draft-doesburg-cfrg-coprf: `HashToScalar` (RFC 9497,
//!   ristretto255-SHA512) over the length-prefixed secret, the label and the length-prefixed
//!   identifier, domain-separated with `"DeriveFactor-" || contextString` of the
//!   the group's [ciphersuite](crate::elgamal::arithmetic::Group::CIPHERSUITE). A factor that is 0 or 1 is rejected
//!   and the derivation retried with the next counter.
//! - `hmac-derivation`: HMAC-SHA512 keyed with the secret over the label and the identifier,
//!   the derivation of libpep 0.13.
//! - `legacy`: the derivation of the legacy PEP repository.
//!
//! The labels are the same in every derivation: `0x01` pseudonym rekey, `0x02` attribute rekey,
//! `0x03` reshuffle.
//!
//! None of these take a [`Ciphersuite`](crate::elgamal::arithmetic::ciphersuite::Ciphersuite): the secret is part of
//! the hash input, so deployments with different secrets already derive unrelated factors, and the
//! domain or session identifier separates within a deployment. See the
//! [`ciphersuite`](crate::elgamal::arithmetic::ciphersuite) module docs.

pub mod generic;

use super::secrets::{EncryptionSecret, PseudonymizationSecret};
use super::types::*;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::Ristretto255;

#[cfg(not(feature = "legacy"))]
pub use generic::{LABEL_REKEY_ATTRIBUTE, LABEL_REKEY_PSEUDONYM, LABEL_RESHUFFLE};

/// Derive a pseudonym rekey factor from a secret and a session.
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> PseudonymRekeyFactor {
    generic::make_pseudonym_rekey_factor::<Ristretto255>(secret, session)
}

/// Derive an attribute rekey factor from a secret and a session.
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> AttributeRekeyFactor {
    generic::make_attribute_rekey_factor::<Ristretto255>(secret, session)
}

/// Derive a pseudonymisation factor from a secret and a domain.
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    generic::make_pseudonymisation_factor::<Ristretto255>(secret, domain)
}

#[cfg(all(test, not(any(feature = "legacy", feature = "hmac-derivation"))))]
mod tests {
    use super::generic::make_factor;
    use super::*;
    use crate::elgamal::arithmetic::hashing::hash_to_scalar_with_dst;
    use crate::elgamal::arithmetic::scalars::ScalarTraits;
    use crate::elgamal::arithmetic::Group;
    use crate::factors::secrets::Secret;

    #[test]
    fn factors_are_deterministic_and_identifier_specific() {
        let secret = Secret::from(b"secret".to_vec());
        let a = make_factor::<Ristretto255>(LABEL_REKEY_PSEUDONYM, &secret, b"a");
        let b = make_factor::<Ristretto255>(LABEL_REKEY_PSEUDONYM, &secret, b"b");
        assert_eq!(
            a,
            make_factor::<Ristretto255>(LABEL_REKEY_PSEUDONYM, &secret, b"a")
        );
        assert_ne!(a, b);
        assert_ne!(
            a,
            make_factor::<Ristretto255>(LABEL_REKEY_ATTRIBUTE, &secret, b"a")
        );
    }

    /// The exact domain separation tag and input encoding of `DeriveFactor`, so that neither can
    /// drift unnoticed: the DST is `"DeriveFactor-" || contextString` of the ciphersuite, and the
    /// input is the length-prefixed secret, the label, the length-prefixed identifier and the
    /// counter.
    #[test]
    fn factors_use_the_ciphersuite_dst() {
        let secret = Secret::from(b"secret".to_vec());
        let id = b"session-a";
        let mut input = Vec::new();
        input.extend_from_slice(&(secret.len() as u16).to_be_bytes());
        input.extend_from_slice(&secret);
        input.push(LABEL_REKEY_PSEUDONYM);
        input.extend_from_slice(&(id.len() as u16).to_be_bytes());
        input.extend_from_slice(id);
        input.push(0u8);
        let dst = Ristretto255::CIPHERSUITE.dst(b"DeriveFactor-");
        assert_eq!(dst, b"DeriveFactor-coPRFV1-ristretto255-SHA512");
        let expected = hash_to_scalar_with_dst(&input, &dst);
        assert_eq!(
            make_factor::<Ristretto255>(LABEL_REKEY_PSEUDONYM, &secret, id).to_bytes(),
            expected.to_bytes()
        );
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
