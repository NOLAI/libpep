use crate::arithmetic::*;
use crate::high_level::{
    Context, EncryptionContext, EncryptionSecret, PseudonymizationContext, PseudonymizationSecret,
    RekeyFactor, ReshuffleFactor, Secret,
};
#[cfg(feature = "legacy-pep-repo-compatible")]
use sha2::Sha256;
use sha2::{Digest, Sha512};

#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    context: &PseudonymizationContext,
) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor("pseudonym", secret, context))
}
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
pub fn make_decryption_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> RekeyFactor {
    RekeyFactor::from(make_factor("decrypt", secret, context))
}

#[cfg(not(feature = "legacy-pep-repo-compatible"))]
fn make_factor(typ: &str, secret: &Secret, context: &Context) -> ScalarNonZero {
    let mut hasher = Sha512::default();
    hasher.update(typ);
    hasher.update(b"|");
    hasher.update(secret.as_bytes());
    hasher.update(b"|");
    hasher.update(context.as_bytes());
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    ScalarNonZero::decode_from_hash(&bytes)
}

#[cfg(feature = "legacy-pep-repo-compatible")]
fn get_audience_type(context: &Context) -> u32 {
    if context.starts_with("USER") {
        0x02
    } else if context.starts_with("SF") {
        0x02
    } else if context.starts_with("AM") {
        0x03
    } else if context.starts_with("TS") {
        0x04
    } else if context.starts_with("RS") {
        0x05
    } else {
        0x00
    }
}
#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_pseudonymisation_factor(
    secret: &PseudonymizationSecret,
    context: &PseudonymizationContext,
) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor(
        secret,
        0x01,
        get_audience_type(context),
        context,
    ))
}
#[cfg(feature = "legacy-pep-repo-compatible")]
pub fn make_decryption_factor(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> RekeyFactor {
    RekeyFactor::from(make_factor(
        secret,
        0x02,
        get_audience_type(context),
        context,
    ))
}

#[cfg(feature = "legacy-pep-repo-compatible")]
fn make_factor(secret: &Secret, typ: u32, audience_type: u32, context: &Context) -> ScalarNonZero {
    let mut hasher_outer = Sha512::default();
    let mut hasher_inner = Sha256::default();

    hasher_inner.update(&typ.to_be_bytes());
    hasher_inner.update(&audience_type.to_be_bytes());
    hasher_inner.update(context.as_bytes());

    hasher_outer.update(secret.as_bytes());
    hasher_outer.update(hasher_inner.finalize());

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher_outer.finalize().as_slice());
    ScalarNonZero::decode_from_hash(&bytes)
}

// CPP implementation that we should be binary compatible with.
//
// CurveScalar PEPSecurity::generateKeyComponent(
//   const std::string& hmacKey,
//   key_component_type_t keyType,
//   AudienceType audienceType,
//   const std::string& payload
// ) const {
//   return CurveScalar::From64Bytes(Sha512::HMac(
//     hmacKey, Sha256().digest(
//       PackUint32BE(uint32_t{keyType}) +
//       PackUint32BE(audienceType) +
//       payload)));
// }

// enum FacilityType {
//   FACILITY_TYPE_UNKNOWN = 0,
//   FACILITY_TYPE_USER = 1,
//   FACILITY_TYPE_STORAGE_FACILITY = 2,
//   FACILITY_TYPE_ACCESS_MANAGER = 3,
//   FACILITY_TYPE_TRANSCRYPTOR = 4,
//   FACILITY_TYPE_REGISTRATION_SERVER = 5
// };