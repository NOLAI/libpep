//! Utilities for deriving factors from contexts and secrets.

use crate::high_level::contexts::*;
use crate::internal::arithmetic::*;
use derive_more::From;
use hmac::{Hmac, Mac};
use sha2::Sha512;
#[cfg(feature = "legacy-pep-repo-compatible")]
use sha2::{Digest, Sha256};

/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from contexts.
pub type Secret = Box<[u8]>;
/// Pseudonymization secret used to derive a [`ReshuffleFactor`] from a [`PseudonymizationContext`](PseudonymizationDomain) (see [`PseudonymizationInfo`]).
#[derive(Clone, Debug, From)]
pub struct PseudonymizationSecret(pub(crate) Secret);
/// Encryption secret used to derive a [`RekeyFactor`] from an [`EncryptionContext`] (see [`AttributeRekeyInfo`] or [`PseudonymRekeyInfo`]).
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
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> PseudonymRekeyFactor {
    PseudonymRekeyFactor::from(make_factor(0x01, &secret.0, context))
}
/// Derive an attribute rekey factor from a secret and a context.
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> AttributeRekeyFactor {
    AttributeRekeyFactor::from(make_factor(0x02, &secret.0, context))
}

/// Derive a pseudonymisation factor from a secret and a context.
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor(0x03, &secret.0, domain))
}

/// Derive a factor from a secret and a context.
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
fn make_factor(typ: u32, secret: &Secret, payload: &String) -> ScalarNonZero {
    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap(); // Use HMAC to prevent length extension attack
    hmac.update(&typ.to_be_bytes());
    hmac.update(payload.as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hmac.finalize().into_bytes());
    ScalarNonZero::decode_from_hash(&bytes)
}

/// Derive a pseudonym rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_pseudonym_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> PseudonymRekeyFactor {
    PseudonymRekeyFactor::from(make_factor(
        &secret.0,
        0x02,
        context.audience_type,
        &context.payload,
    ))
}
/// Derive an attribute rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_attribute_rekey_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> AttributeRekeyFactor {
    AttributeRekeyFactor::from(make_factor(
        &secret.0,
        0x01,
        context.audience_type,
        &context.payload,
    ))
}

/// Derive a pseudonymisation factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    payload: &PseudonymizationDomain,
) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor(
        &secret.0,
        0x01,
        payload.audience_type,
        &payload.payload,
    ))
}

/// Derive a factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy-pep-repo-compatible")]
fn make_factor(secret: &Secret, typ: u32, audience_type: u32, payload: &String) -> ScalarNonZero {
    let mut hasher_inner = Sha256::default();
    hasher_inner.update(typ.to_be_bytes());
    hasher_inner.update(audience_type.to_be_bytes());
    hasher_inner.update(payload.as_bytes());
    let result_inner = hasher_inner.finalize();

    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap(); // Use HMAC to prevent length extension attack
    hmac.update(&result_inner);
    let result_outer = hmac.finalize().into_bytes();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&result_outer);
    ScalarNonZero::decode_from_hash(&bytes)
}
