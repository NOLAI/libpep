use crate::arithmetic::*;
use crate::high_level::contexts::*;
use crate::high_level::keys::{EncryptionSecret, PseudonymizationSecret, Secret};

use hmac::{Hmac, Mac};
use sha2::Sha512;
#[cfg(feature = "legacy-pep-repo-compatible")]
use sha2::{Digest, Sha256};

#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    context: &PseudonymizationContext,
) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor("pseudonym", &secret.0, context))
}
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_rekey_factor(secret: &EncryptionSecret, context: &EncryptionContext) -> RekeyFactor {
    RekeyFactor::from(make_factor("rekey", &secret.0, context))
}

#[cfg(not(feature = "legacy-pep-repo-compatible"))]
fn make_factor(typ: &str, secret: &Secret, context: &Context) -> ScalarNonZero {
    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap(); // Use HMAC to prevent length extension attack
    hmac.update(typ.as_bytes());
    hmac.update(b"|");
    hmac.update(context.as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hmac.finalize().into_bytes().as_slice());
    ScalarNonZero::decode_from_hash(&bytes)
}

#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    context: &PseudonymizationContext,
) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor(
        &secret.0,
        0x01,
        context.audience_type,
        &context.payload,
    ))
}
#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_rekey_factor(secret: &EncryptionSecret, context: &EncryptionContext) -> RekeyFactor {
    RekeyFactor::from(make_factor(
        &secret.0,
        0x02,
        context.audience_type,
        &context.payload,
    ))
}

#[cfg(feature = "legacy-pep-repo-compatible")]
fn make_factor(
    secret: &Secret,
    typ: u32,
    audience_type: u32,
    context: &Context,
) -> ScalarNonZero {
    let mut hasher_inner = Sha256::default(); // Use HMAC to prevent length extension attack
    hasher_inner.update(&typ.to_be_bytes());
    hasher_inner.update(audience_type.to_be_bytes());
    hasher_inner.update(&context.as_bytes());
    let result_inner = hasher_inner.finalize();

    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
    hmac.update(result_inner.as_slice());
    let result_outer = hmac.finalize().into_bytes();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(result_outer.as_slice());
    ScalarNonZero::decode_from_hash(&bytes)
}
