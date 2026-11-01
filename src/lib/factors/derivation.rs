//! Derivation of factors from secrets and contexts, and of the info for a transcryption between
//! two contexts.
//!
//! The [`Ciphersuite`] supplies the hash and the domain separation tag.
//!
//! Two derivations exist, selected by feature:
//!
//! - The default is `DeriveFactor`: `HashToScalar` over the length-prefixed secret, the label and
//!   the length-prefixed identifier, domain-separated with `"DeriveFactor-" || contextString` of
//!   the [ciphersuite](crate::elgamal::arithmetic::Ciphersuite::ID). A factor that is 0 or 1 is
//!   rejected and the derivation retried with the next counter.
//! - `legacy`: the derivation of the legacy PEP repository, which it reproduces bit for bit.
//!
//! The labels differ: the default uses `0x01` for a pseudonym rekey factor, `0x02` for an
//! attribute rekey factor and `0x03` for a reshuffle factor; the legacy derivation uses `0x02`
//! for a pseudonym rekey factor and `0x01` for the other two, with the audience type.
//!
//! The secret is part of the hash input, so deployments with different secrets derive unrelated
//! factors, and the domain or session identifier separates within a deployment. The ciphersuite
//! adds its tag on top (see [`ciphersuite`](crate::elgamal::arithmetic::ciphersuite)).

use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::{Ciphersuite, Group, Ristretto255Sha512};
use crate::factors::secrets::{PseudonymizationSecret, RekeyingSecret, Secret};
use crate::factors::types::*;
#[cfg(feature = "legacy")]
use hmac::{Hmac, KeyInit, Mac};
#[cfg(feature = "legacy")]
use sha2::Sha512;
#[cfg(feature = "legacy")]
use sha2::{Digest, Sha256};

/// Secrets, domains and contexts must be shorter than this many bytes: the derivation
/// length-prefixes them with two bytes. Callers that take them from untrusted input check the
/// length first; the derivation panics past it.
pub const MAX_INPUT_LENGTH: usize = 1 << 16;

/// Label of the pseudonym rekey factor `k_c` (`labelRekeyPseudonym`).
pub const LABEL_REKEY_PSEUDONYM: u8 = 0x01;
/// Label of the attribute rekey factor `k'_c` (`labelRekeyAttribute`).
pub const LABEL_REKEY_ATTRIBUTE: u8 = 0x02;
/// Label of the reshuffle factor `s_d` (`labelReshuffle`).
pub const LABEL_RESHUFFLE: u8 = 0x03;

/// Derive a pseudonym rekey factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonym_rekey_factor_generic<C: Ciphersuite>(
    secret: &RekeyingSecret,
    session: &EncryptionContext,
) -> PseudonymRekeyFactor<C::Group> {
    match session {
        EncryptionContext::Specific(payload) => PseudonymRekeyFactor(make_factor::<C>(
            LABEL_REKEY_PSEUDONYM,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context: return identity factor
            PseudonymRekeyFactor(C::Group::scalar_one())
        }
    }
}

/// Derive a pseudonym rekey factor from a secret and a context, for ristretto255 with SHA-512.
///
/// See [`make_pseudonym_rekey_factor_generic`] for another ciphersuite.
pub fn make_pseudonym_rekey_factor(
    secret: &RekeyingSecret,
    session: &EncryptionContext,
) -> PseudonymRekeyFactor {
    make_pseudonym_rekey_factor_generic::<Ristretto255Sha512>(secret, session)
}

/// Derive an attribute rekey factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_attribute_rekey_factor_generic<C: Ciphersuite>(
    secret: &RekeyingSecret,
    session: &EncryptionContext,
) -> AttributeRekeyFactor<C::Group> {
    match session {
        EncryptionContext::Specific(payload) => AttributeRekeyFactor(make_factor::<C>(
            LABEL_REKEY_ATTRIBUTE,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context: return identity factor
            AttributeRekeyFactor(C::Group::scalar_one())
        }
    }
}

/// Derive an attribute rekey factor from a secret and a context, for ristretto255 with SHA-512.
///
/// See [`make_attribute_rekey_factor_generic`] for another ciphersuite.
pub fn make_attribute_rekey_factor(
    secret: &RekeyingSecret,
    session: &EncryptionContext,
) -> AttributeRekeyFactor {
    make_attribute_rekey_factor_generic::<Ristretto255Sha512>(secret, session)
}

/// Derive a pseudonymization factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonymization_factor_generic<C: Ciphersuite>(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor<C::Group> {
    match domain {
        PseudonymizationDomain::Specific(payload) => ReshuffleFactor(make_factor::<C>(
            LABEL_RESHUFFLE,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "global-pseudonyms")]
        PseudonymizationDomain::Global => {
            // Global domain: return identity factor
            ReshuffleFactor(C::Group::scalar_one())
        }
    }
}

/// Derive a pseudonymization factor from a secret and a context, for ristretto255 with SHA-512.
///
/// See [`make_pseudonymization_factor_generic`] for another ciphersuite.
pub fn make_pseudonymization_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    make_pseudonymization_factor_generic::<Ristretto255Sha512>(secret, domain)
}

/// `DeriveFactor(secret, label, id)` .
///
/// # Panics
///
/// Panics if `secret` or `id` is [`MAX_INPUT_LENGTH`] bytes or
/// longer; the derivation input length-prefixes both with two bytes.
#[cfg(not(feature = "legacy"))]
pub(crate) fn make_factor<C: Ciphersuite>(
    label: u8,
    secret: &Secret,
    id: &[u8],
) -> <C::Group as Group>::Scalar {
    let secret_len = u16::try_from(secret.len()).ok();
    let id_len = u16::try_from(id.len()).ok();
    let (Some(secret_len), Some(id_len)) = (secret_len, id_len) else {
        panic!("DeriveFactor: secrets and identifiers must be shorter than 2^16 bytes");
    };
    let dst = C::ID.dst(b"DeriveFactor-");
    let mut input = Vec::with_capacity(secret.len() + id.len() + 6);
    input.extend_from_slice(&secret_len.to_be_bytes());
    input.extend_from_slice(secret);
    input.push(label);
    input.extend_from_slice(&id_len.to_be_bytes());
    input.extend_from_slice(id);
    // A factor must be neither 0 (which would destroy the ciphertext) nor 1 (which would apply no
    // transformation). Both occur with probability about 2^-252; if they do, the derivation is
    // retried with the next counter, so that it stays total and deterministic.
    for counter in 0u8..=255 {
        input.push(counter);
        let scalar = C::hash_to_scalar(&input, &dst).filter(|s| *s != C::Group::scalar_one());
        input.pop();
        if let Some(factor) = scalar {
            return factor;
        }
    }
    unreachable!("256 consecutive degenerate factor derivations")
}

/// Derive a pseudonym rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_pseudonym_rekey_factor_generic<C: Ciphersuite>(
    secret: &RekeyingSecret,
    context: &EncryptionContext,
) -> PseudonymRekeyFactor<C::Group> {
    match context {
        EncryptionContext::Specific {
            payload,
            audience_type,
        } => PseudonymRekeyFactor(make_factor::<C>(&secret.0, 0x02, *audience_type, payload)),
        EncryptionContext::Global => {
            // Global context: return identity factor
            PseudonymRekeyFactor(C::Group::scalar_one())
        }
    }
}

/// Derive an attribute rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_attribute_rekey_factor_generic<C: Ciphersuite>(
    secret: &RekeyingSecret,
    context: &EncryptionContext,
) -> AttributeRekeyFactor<C::Group> {
    match context {
        EncryptionContext::Specific {
            payload,
            audience_type,
        } => AttributeRekeyFactor(make_factor::<C>(&secret.0, 0x01, *audience_type, payload)),
        EncryptionContext::Global => {
            // Global context: return identity factor
            AttributeRekeyFactor(C::Group::scalar_one())
        }
    }
}

/// Derive a pseudonymization factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_pseudonymization_factor_generic<C: Ciphersuite>(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor<C::Group> {
    match domain {
        PseudonymizationDomain::Specific {
            payload,
            audience_type,
        } => ReshuffleFactor(make_factor::<C>(&secret.0, 0x01, *audience_type, payload)),
        PseudonymizationDomain::Global => {
            // Global domain: return identity factor
            ReshuffleFactor(C::Group::scalar_one())
        }
    }
}

/// Derive a factor from a secret and a context (using the legacy PEP repo method).
///
/// As in the legacy implementation, a zero result is mapped to one.
#[cfg(feature = "legacy")]
fn make_factor<C: Ciphersuite>(
    secret: &Secret,
    typ: u32,
    audience_type: u32,
    payload: &String,
) -> <C::Group as Group>::Scalar {
    let mut hasher_inner = Sha256::default();
    hasher_inner.update(typ.to_be_bytes());
    hasher_inner.update(audience_type.to_be_bytes());
    hasher_inner.update(payload.as_bytes());
    let result_inner = hasher_inner.finalize();

    // Unwrap is safe: HMAC-SHA512 accepts keys of any length
    #[allow(clippy::unwrap_used)]
    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
    hmac.update(&result_inner);
    let result_outer = hmac.finalize().into_bytes();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&result_outer);
    C::Group::scalar_from_uniform_bytes(&bytes).unwrap_or_else(C::Group::scalar_one)
}

impl<G: Group> PseudonymizationInfo<G> {
    /// Compute the pseudonymization info given pseudonymization domains, sessions and secrets.
    pub fn new_generic<C: Ciphersuite<Group = G>>(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        let s_from =
            make_pseudonymization_factor_generic::<C>(pseudonymization_secret, domain_from);
        let s_to = make_pseudonymization_factor_generic::<C>(pseudonymization_secret, domain_to);
        Self {
            s: ReshuffleFactor(C::Group::scalar_inverse(&s_from.0) * s_to.0),
            k: PseudonymRekeyInfo::new_generic::<C>(session_from, session_to, rekeying_secret).k,
        }
    }
}

impl PseudonymizationInfo {
    /// Compute the pseudonymization info given pseudonymization domains, sessions and secrets, for ristretto255 with SHA-512.
    ///
    /// See [`new_generic`](PseudonymizationInfo::new_generic) for another ciphersuite.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        Self::new_generic::<Ristretto255Sha512>(
            domain_from,
            domain_to,
            session_from,
            session_to,
            pseudonymization_secret,
            rekeying_secret,
        )
    }
}

impl<G: Group> PseudonymRekeyInfo<G> {
    /// Compute the rekey info for pseudonyms given sessions and secrets.
    pub fn new_generic<C: Ciphersuite<Group = G>>(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        let k_from = make_pseudonym_rekey_factor_generic::<C>(rekeying_secret, session_from);
        let k_to = make_pseudonym_rekey_factor_generic::<C>(rekeying_secret, session_to);
        Self {
            k: PseudonymRekeyFactor(C::Group::scalar_inverse(&k_from.0) * k_to.0),
        }
    }
}

impl PseudonymRekeyInfo {
    /// Compute the rekey info for pseudonyms given sessions and secrets, for ristretto255 with SHA-512.
    ///
    /// See [`new_generic`](PseudonymRekeyInfo::new_generic) for another ciphersuite.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        Self::new_generic::<Ristretto255Sha512>(session_from, session_to, rekeying_secret)
    }
}

impl<G: Group> AttributeRekeyInfo<G> {
    /// Compute the rekey info for attributes given sessions and secrets.
    pub fn new_generic<C: Ciphersuite<Group = G>>(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        let k_from = make_attribute_rekey_factor_generic::<C>(rekeying_secret, session_from);
        let k_to = make_attribute_rekey_factor_generic::<C>(rekeying_secret, session_to);
        Self {
            k: AttributeRekeyFactor(C::Group::scalar_inverse(&k_from.0) * k_to.0),
        }
    }
}

impl AttributeRekeyInfo {
    /// Compute the rekey info for attributes given sessions and secrets, for ristretto255 with SHA-512.
    ///
    /// See [`new_generic`](AttributeRekeyInfo::new_generic) for another ciphersuite.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        Self::new_generic::<Ristretto255Sha512>(session_from, session_to, rekeying_secret)
    }
}

impl<G: Group> TranscryptionInfo<G> {
    /// Compute the transcryption info given pseudonymization domains, sessions and secrets.
    pub fn new_generic<C: Ciphersuite<Group = G>>(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        Self {
            pseudonym: PseudonymizationInfo::new_generic::<C>(
                domain_from,
                domain_to,
                session_from,
                session_to,
                pseudonymization_secret,
                rekeying_secret,
            ),
            attribute: AttributeRekeyInfo::new_generic::<C>(
                session_from,
                session_to,
                rekeying_secret,
            ),
        }
    }
}

impl TranscryptionInfo {
    /// Compute the transcryption info given pseudonymization domains, sessions and secrets, for ristretto255 with SHA-512.
    ///
    /// See [`new_generic`](TranscryptionInfo::new_generic) for another ciphersuite.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        rekeying_secret: &RekeyingSecret,
    ) -> Self {
        Self::new_generic::<Ristretto255Sha512>(
            domain_from,
            domain_to,
            session_from,
            session_to,
            pseudonymization_secret,
            rekeying_secret,
        )
    }
}

#[cfg(all(test, not(feature = "legacy")))]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::hashing::hash_to_scalar_with_dst;
    use crate::elgamal::arithmetic::scalars::ScalarTraits;
    use crate::elgamal::arithmetic::{Ciphersuite, Ristretto255Sha512};
    use crate::factors::secrets::Secret;
    use crate::factors::Factor;

    #[test]
    fn factors_are_deterministic_and_identifier_specific() {
        let secret = Secret::from(b"secret".to_vec());
        let a = make_factor::<Ristretto255Sha512>(LABEL_REKEY_PSEUDONYM, &secret, b"a");
        let b = make_factor::<Ristretto255Sha512>(LABEL_REKEY_PSEUDONYM, &secret, b"b");
        assert_eq!(
            a,
            make_factor::<Ristretto255Sha512>(LABEL_REKEY_PSEUDONYM, &secret, b"a")
        );
        assert_ne!(a, b);
        assert_ne!(
            a,
            make_factor::<Ristretto255Sha512>(LABEL_REKEY_ATTRIBUTE, &secret, b"a")
        );
    }

    /// The domain separation tag and input encoding of `DeriveFactor`, so that neither can
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
        let dst = Ristretto255Sha512::ID.dst(b"DeriveFactor-");
        assert_eq!(dst, b"DeriveFactor-nPEPV1-ristretto255-SHA512");
        let expected = hash_to_scalar_with_dst(&input, &dst);
        assert_eq!(
            make_factor::<Ristretto255Sha512>(LABEL_REKEY_PSEUDONYM, &secret, id).to_bytes(),
            expected.to_bytes()
        );
    }

    #[test]
    fn info_is_the_factor_ratio() {
        let secret = RekeyingSecret::from(b"secret".to_vec());
        let from = EncryptionContext::from("from");
        let to = EncryptionContext::from("to");
        let info = PseudonymRekeyInfo::new(&from, &to, &secret);
        let k_from = make_pseudonym_rekey_factor(&secret, &from);
        let k_to = make_pseudonym_rekey_factor(&secret, &to);
        assert_eq!(k_from.scalar() * info.k.scalar(), k_to.scalar());
        assert_eq!(info.reverse().reverse(), info);
    }
}
