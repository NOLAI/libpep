//! Derivation of factors from secrets and contexts, and of the info for a transcryption between
//! two contexts.

use super::secrets::{EncryptionSecret, PseudonymizationSecret, Secret};
use super::types::*;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
#[cfg(not(feature = "legacy"))]
use crate::elgamal::arithmetic::scalars::{ScalarCanBeZero, ScalarTraits};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
#[cfg(feature = "legacy")]
use sha2::{Digest, Sha256};

/// Derive a pseudonym rekey factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> PseudonymRekeyFactor {
    match context {
        EncryptionContext::Specific(payload) => {
            PseudonymRekeyFactor(make_factor(0x01, &secret.0, payload))
        }
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context - return identity factor
            PseudonymRekeyFactor(ScalarNonZero::one())
        }
    }
}

/// Derive an attribute rekey factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> AttributeRekeyFactor {
    match context {
        EncryptionContext::Specific(payload) => {
            AttributeRekeyFactor(make_factor(0x02, &secret.0, payload))
        }
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context - return identity factor
            AttributeRekeyFactor(ScalarNonZero::one())
        }
    }
}

/// Derive a pseudonymisation factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    match domain {
        PseudonymizationDomain::Specific(payload) => {
            ReshuffleFactor(make_factor(0x03, &secret.0, payload))
        }
        #[cfg(feature = "global-pseudonyms")]
        PseudonymizationDomain::Global => {
            // Global domain - return identity factor
            ReshuffleFactor(ScalarNonZero::one())
        }
    }
}

/// Derive a factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
fn make_factor(typ: u32, secret: &Secret, payload: &String) -> ScalarNonZero {
    // A factor must be neither 0 (which would destroy the ciphertext) nor 1 (which would apply no
    // transformation). Both occur with probability about 2^-252; if they do, the derivation is
    // retried with a counter appended, so that the derivation stays total and deterministic. The
    // counter is only appended on retry, so factors are unchanged in the overwhelmingly common
    // case.
    for counter in 0u8..=255 {
        // Unwrap is safe: HMAC-SHA512 accepts keys of any length
        #[allow(clippy::unwrap_used)]
        let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
        hmac.update(&typ.to_be_bytes());
        hmac.update(payload.as_bytes());
        if counter > 0 {
            hmac.update(&[counter]);
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&hmac.finalize().into_bytes());
        if let Some(factor) = scalar_from_hash_excluding_zero_and_one(&bytes) {
            return factor;
        }
    }
    unreachable!("256 consecutive degenerate factor derivations")
}

/// Reduce a 64-byte hash to a scalar, rejecting 0 and 1.
#[cfg(not(feature = "legacy"))]
fn scalar_from_hash_excluding_zero_and_one(bytes: &[u8; 64]) -> Option<ScalarNonZero> {
    let scalar = ScalarCanBeZero::from_hash(bytes);
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
    context: &EncryptionContext,
) -> PseudonymRekeyFactor {
    match context {
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
    context: &EncryptionContext,
) -> AttributeRekeyFactor {
    match context {
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
        let zero = [0u8; 64];
        assert!(scalar_from_hash_excluding_zero_and_one(&zero).is_none());
        let mut one = [0u8; 64];
        one[0] = 1;
        assert!(scalar_from_hash_excluding_zero_and_one(&one).is_none());
        let mut two = [0u8; 64];
        two[0] = 2;
        assert!(scalar_from_hash_excluding_zero_and_one(&two).is_some());
    }

    #[test]
    fn factors_are_deterministic_and_context_specific() {
        let secret = Secret::from(b"secret".to_vec());
        let a = make_factor(1, &secret, &"a".to_string());
        let b = make_factor(1, &secret, &"b".to_string());
        assert_eq!(a, make_factor(1, &secret, &"a".to_string()));
        assert_ne!(a, b);
        assert_ne!(a, make_factor(2, &secret, &"a".to_string()));
    }
}
