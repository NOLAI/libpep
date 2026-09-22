//! Derivation of factors from secrets and contexts, and of the info for a transcryption between
//! two contexts.
//!
//! Three derivations exist, selected by feature:
//!
//! - The default is `DeriveFactor` of draft-doesburg-cfrg-coprf: `HashToScalar` (RFC 9497,
//!   ristretto255-SHA512) over the length-prefixed secret, the label and the length-prefixed
//!   identifier, domain-separated with `"DeriveFactor-" || contextString` of the
//!   [ciphersuite context](crate::protocol::ciphersuite). A factor that is 0 or 1 is rejected and
//!   the derivation retried with the next counter.
//! - `hmac-derivation`: HMAC-SHA512 keyed with the secret over the label and the identifier,
//!   the derivation of libpep 0.13.
//! - `legacy`: the derivation of the legacy PEP repository.
//!
//! The labels are the same in every derivation: `0x01` pseudonym rekey, `0x02` attribute rekey,
//! `0x03` reshuffle.
//!
//! None of these take a protocol [`Context`](crate::protocol::Context): the secret is part of the
//! hash input, so deployments with different secrets already derive unrelated factors, and the
//! domain or session identifier separates within a deployment. See the
//! [`protocol`](crate::protocol) module docs.

use super::secrets::{EncryptionSecret, PseudonymizationSecret, Secret};
use super::types::*;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
#[cfg(not(feature = "legacy"))]
use crate::elgamal::arithmetic::scalars::{ScalarCanBeZero, ScalarTraits};
#[cfg(any(feature = "legacy", feature = "hmac-derivation"))]
use hmac::{Hmac, KeyInit, Mac};
#[cfg(any(feature = "legacy", feature = "hmac-derivation"))]
use sha2::Sha512;
#[cfg(feature = "legacy")]
use sha2::{Digest, Sha256};

#[cfg(all(feature = "legacy", feature = "hmac-derivation"))]
compile_error!("the `legacy` and `hmac-derivation` features select different factor derivations and cannot be combined");

/// Label of the pseudonym rekey factor `k_c` (`labelRekeyPseudonym`).
pub const LABEL_REKEY_PSEUDONYM: u8 = 0x01;
/// Label of the attribute rekey factor `k'_c` (`labelRekeyAttribute`).
pub const LABEL_REKEY_ATTRIBUTE: u8 = 0x02;
/// Label of the reshuffle factor `s_d` (`labelReshuffle`).
pub const LABEL_RESHUFFLE: u8 = 0x03;

/// Derive the pseudonym rekey factor of a session from an encryption secret.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> PseudonymRekeyFactor {
    match session {
        EncryptionContext::Specific(payload) => PseudonymRekeyFactor(make_factor(
            LABEL_REKEY_PSEUDONYM,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context - return identity factor
            PseudonymRekeyFactor(ScalarNonZero::one())
        }
    }
}

/// Derive the attribute rekey factor of a session from an encryption secret.
#[cfg(not(feature = "legacy"))]
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> AttributeRekeyFactor {
    match session {
        EncryptionContext::Specific(payload) => AttributeRekeyFactor(make_factor(
            LABEL_REKEY_ATTRIBUTE,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context - return identity factor
            AttributeRekeyFactor(ScalarNonZero::one())
        }
    }
}

/// Derive the reshuffle factor of a domain from a pseudonymization secret.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    match domain {
        PseudonymizationDomain::Specific(payload) => {
            ReshuffleFactor(make_factor(LABEL_RESHUFFLE, &secret.0, payload.as_bytes()))
        }
        #[cfg(feature = "global-pseudonyms")]
        PseudonymizationDomain::Global => {
            // Global domain - return identity factor
            ReshuffleFactor(ScalarNonZero::one())
        }
    }
}

/// `DeriveFactor(secret, label, id)` of draft-doesburg-cfrg-coprf.
///
/// # Panics
///
/// Panics if `secret` or `id` is 2^16 bytes or longer; the derivation input length-prefixes
/// both with two bytes.
#[cfg(not(any(feature = "legacy", feature = "hmac-derivation")))]
fn make_factor(label: u8, secret: &Secret, id: &[u8]) -> ScalarNonZero {
    use crate::elgamal::arithmetic::hashing::hash_to_scalar;

    let secret_len = u16::try_from(secret.len()).ok();
    let id_len = u16::try_from(id.len()).ok();
    let (Some(secret_len), Some(id_len)) = (secret_len, id_len) else {
        panic!("DeriveFactor: secrets and identifiers must be shorter than 2^16 bytes");
    };
    let dst = crate::protocol::ciphersuite().dst(b"DeriveFactor-");
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
        let scalar = hash_to_scalar(&input, &dst);
        input.pop();
        if let Some(factor) = non_degenerate(scalar) {
            return factor;
        }
    }
    unreachable!("256 consecutive degenerate factor derivations")
}

/// Derive a factor with HMAC-SHA512 keyed with the secret, the derivation of libpep 0.13.
#[cfg(feature = "hmac-derivation")]
fn make_factor(label: u8, secret: &Secret, id: &[u8]) -> ScalarNonZero {
    // Retried with a counter appended only on a degenerate result, so factors are unchanged in
    // the overwhelmingly common case.
    for counter in 0u8..=255 {
        // Unwrap is safe: HMAC-SHA512 accepts keys of any length
        #[allow(clippy::unwrap_used)]
        let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
        hmac.update(&u32::from(label).to_be_bytes());
        hmac.update(id);
        if counter > 0 {
            hmac.update(&[counter]);
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&hmac.finalize().into_bytes());
        if let Some(factor) = non_degenerate(ScalarCanBeZero::from_hash(&bytes)) {
            return factor;
        }
    }
    unreachable!("256 consecutive degenerate factor derivations")
}

/// The scalar as a factor, or `None` if it is 0 or 1.
#[cfg(not(feature = "legacy"))]
fn non_degenerate(scalar: ScalarCanBeZero) -> Option<ScalarNonZero> {
    if scalar.is_zero() || scalar == ScalarCanBeZero::one() {
        None
    } else {
        ScalarNonZero::from_bytes(&scalar.to_bytes())
    }
}

/// Derive a pseudonym rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> PseudonymRekeyFactor {
    match session {
        EncryptionContext::Specific {
            payload,
            audience_type,
        } => PseudonymRekeyFactor(make_factor(&secret.0, 0x02, *audience_type, payload)),
        EncryptionContext::Global => {
            // Global context - return identity factor
            PseudonymRekeyFactor(ScalarNonZero::one())
        }
    }
}

/// Derive an attribute rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> AttributeRekeyFactor {
    match session {
        EncryptionContext::Specific {
            payload,
            audience_type,
        } => AttributeRekeyFactor(make_factor(&secret.0, 0x01, *audience_type, payload)),
        EncryptionContext::Global => {
            // Global context - return identity factor
            AttributeRekeyFactor(ScalarNonZero::one())
        }
    }
}

/// Derive a pseudonymisation factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    match domain {
        PseudonymizationDomain::Specific {
            payload,
            audience_type,
        } => ReshuffleFactor(make_factor(&secret.0, 0x01, *audience_type, payload)),
        PseudonymizationDomain::Global => {
            // Global domain - return identity factor
            ReshuffleFactor(ScalarNonZero::one())
        }
    }
}

/// Derive a factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
fn make_factor(secret: &Secret, typ: u32, audience_type: u32, payload: &String) -> ScalarNonZero {
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
    ScalarNonZero::from_hash(&bytes)
}

impl PseudonymizationInfo {
    /// Compute the pseudonymization info given pseudonymization domains, sessions and secrets.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(pseudonymization_secret, domain_from);
        let s_to = make_pseudonymisation_factor(pseudonymization_secret, domain_to);
        Self {
            s: ReshuffleFactor(s_from.0.invert() * s_to.0),
            k: PseudonymRekeyInfo::new(session_from, session_to, encryption_secret).k,
        }
    }
}

impl PseudonymRekeyInfo {
    /// Compute the rekey info for pseudonyms given sessions and secrets.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_pseudonym_rekey_factor(encryption_secret, session_from);
        let k_to = make_pseudonym_rekey_factor(encryption_secret, session_to);
        Self {
            k: PseudonymRekeyFactor(k_from.0.invert() * k_to.0),
        }
    }
}

impl AttributeRekeyInfo {
    /// Compute the rekey info for attributes given sessions and secrets.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_attribute_rekey_factor(encryption_secret, session_from);
        let k_to = make_attribute_rekey_factor(encryption_secret, session_to);
        Self {
            k: AttributeRekeyFactor(k_from.0.invert() * k_to.0),
        }
    }
}

impl TranscryptionInfo {
    /// Compute the transcryption info given pseudonymization domains, sessions and secrets.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        Self {
            pseudonym: PseudonymizationInfo::new(
                domain_from,
                domain_to,
                session_from,
                session_to,
                pseudonymization_secret,
                encryption_secret,
            ),
            attribute: AttributeRekeyInfo::new(session_from, session_to, encryption_secret),
        }
    }
}

#[cfg(all(test, not(feature = "legacy")))]
mod tests {
    use super::*;

    #[test]
    fn degenerate_scalars_are_rejected() {
        assert!(non_degenerate(ScalarCanBeZero::zero()).is_none());
        assert!(non_degenerate(ScalarCanBeZero::one()).is_none());
        let mut two = [0u8; 64];
        two[0] = 2;
        assert!(non_degenerate(ScalarCanBeZero::from_hash(&two)).is_some());
    }

    #[test]
    fn factors_are_deterministic_and_input_specific() {
        let secret = Secret::from(b"secret".to_vec());
        let a = make_factor(1, &secret, b"a");
        assert_eq!(a, make_factor(1, &secret, b"a"));
        assert_ne!(a, make_factor(1, &secret, b"b"));
        assert_ne!(a, make_factor(2, &secret, b"a"));
        assert_ne!(a, make_factor(1, &Secret::from(b"other".to_vec()), b"a"));
    }

    /// The derivation is domain-separated with the ciphersuite context, so a factor equals
    /// `HashToScalar` under `"DeriveFactor-" || contextString` over the length-prefixed input.
    /// This pins both the DST and the input encoding.
    #[test]
    #[cfg(not(feature = "hmac-derivation"))]
    fn factors_use_the_ciphersuite_dst() {
        use crate::elgamal::arithmetic::hashing::hash_to_scalar;

        let secret = Secret::from(b"secret".to_vec());
        let expected = hash_to_scalar(
            b"\x00\x06secret\x01\x00\x02id\x00",
            b"DeriveFactor-coPRFV1-\x00-ristretto255-SHA512",
        );
        assert_eq!(
            make_factor(1, &secret, b"id").to_bytes(),
            expected.to_bytes()
        );
    }

    /// Length prefixes keep the secret and the identifier apart: moving a byte from one to the
    /// other changes the factor.
    #[test]
    #[cfg(not(feature = "hmac-derivation"))]
    fn secret_and_identifier_are_length_prefixed() {
        let a = make_factor(1, &Secret::from(b"secretx".to_vec()), b"id");
        let b = make_factor(1, &Secret::from(b"secret".to_vec()), b"xid");
        assert_ne!(a, b);
    }

    #[test]
    fn global_contexts_give_identity_factors() {
        #[cfg(feature = "offline")]
        {
            let secret = EncryptionSecret::from(b"secret".to_vec());
            assert_eq!(
                make_pseudonym_rekey_factor(&secret, &EncryptionContext::global()).0,
                ScalarNonZero::one()
            );
            assert_eq!(
                make_attribute_rekey_factor(&secret, &EncryptionContext::global()).0,
                ScalarNonZero::one()
            );
        }
        #[cfg(feature = "global-pseudonyms")]
        {
            let secret = PseudonymizationSecret::from(b"secret".to_vec());
            assert_eq!(
                make_pseudonymisation_factor(&secret, &PseudonymizationDomain::global()).0,
                ScalarNonZero::one()
            );
        }
    }
}
