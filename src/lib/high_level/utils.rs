//! Utilities for deriving factors from contexts and secrets.

use crate::high_level::contexts::*;
use crate::high_level::keys::{EncryptionSecret, PseudonymizationSecret, Secret};
use crate::internal::arithmetic::*;
use hmac::{Hmac, Mac};
use sha2::Sha512;
#[cfg(feature = "legacy-pep-repo-compatible")]
use sha2::{Digest, Sha256};

/// Derive a pseudonymisation factor from a secret and a context.
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor("pseudonym", &secret.0, domain))
}
/// Derive a rekey factor from a secret and a context.
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_rekey_factor(secret: &EncryptionSecret, context: &EncryptionContext) -> RekeyFactor {
    RekeyFactor::from(make_factor("rekey", &secret.0, context))
}

/// Derive a factor from a secret and a context.
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
fn make_factor(typ: &str, secret: &Secret, payload: &String) -> ScalarNonZero {
    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap(); // Use HMAC to prevent length extension attack
    hmac.update(typ.as_bytes());
    hmac.update(b"|");
    hmac.update(payload.as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hmac.finalize().into_bytes().as_slice());
    ScalarNonZero::decode_from_hash(&bytes)
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
/// Derive a rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_rekey_factor(secret: &EncryptionSecret, context: &EncryptionContext) -> RekeyFactor {
    RekeyFactor::from(make_factor(
        &secret.0,
        0x02,
        context.audience_type,
        &context.payload,
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
    hmac.update(result_inner.as_slice());
    let result_outer = hmac.finalize().into_bytes();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(result_outer.as_slice());
    ScalarNonZero::decode_from_hash(&bytes)
}
