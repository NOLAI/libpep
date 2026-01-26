//! Secret types and functions for deriving cryptographic factors from contexts and secrets.

use super::types::*;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::factors::contexts::{EncryptionContext, PseudonymizationDomain};
use derive_more::From;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
#[cfg(feature = "legacy")]
use sha2::{Digest, Sha256};

/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from contexts.
pub type Secret = Box<[u8]>;

/// Pseudonymization secret used to derive a [`ReshuffleFactor`](ReshuffleFactor) from a [`PseudonymizationDomain`](PseudonymizationDomain).
#[derive(Clone, Debug, From)]
pub struct PseudonymizationSecret(pub(crate) Secret);

/// Encryption secret used to derive rekey factors from an [`EncryptionContext`](EncryptionContext).
#[derive(Clone, Debug, From)]
pub struct EncryptionSecret(pub(crate) Secret);

impl PseudonymizationSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}

impl EncryptionSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}

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
    // Unwrap is safe: HMAC-SHA512 accepts keys of any length
    #[allow(clippy::unwrap_used)]
    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
    hmac.update(&typ.to_be_bytes());
    hmac.update(payload.as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hmac.finalize().into_bytes());
    ScalarNonZero::from_hash(&bytes)
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

// Info implementations with new() and reverse() methods

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
        let reshuffle_factor = ReshuffleFactor(s_from.0.invert() * s_to.0);
        let rekey_factor = PseudonymRekeyInfo::new(session_from, session_to, encryption_secret);
        Self {
            s: reshuffle_factor,
            k: rekey_factor,
        }
    }

    /// Reverse the pseudonymization info (i.e., switch the direction of the pseudonymization).
    pub fn reverse(&self) -> Self {
        Self {
            s: ReshuffleFactor(self.s.0.invert()),
            k: PseudonymRekeyFactor(self.k.0.invert()),
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
        PseudonymRekeyFactor(k_from.0.invert() * k_to.0)
    }

    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        PseudonymRekeyFactor(self.0.invert())
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
        AttributeRekeyFactor(k_from.0.invert() * k_to.0)
    }

    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        AttributeRekeyFactor(self.0.invert())
    }
}
