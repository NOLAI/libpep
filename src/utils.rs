use crate::arithmetic::*;
use crate::high_level::{Context, EncryptionContext, EncryptionSecret, PseudonymizationContext, PseudonymizationSecret, RekeyFactor, ReshuffleFactor, Secret};
use sha2::{Digest, Sha512};

pub fn make_pseudonymisation_factor(secret: &PseudonymizationSecret, context: &PseudonymizationContext) -> ReshuffleFactor {
    ReshuffleFactor::from(make_factor("pseudonym", secret, context))
}
pub fn make_decryption_factor(secret: &EncryptionSecret, context: &EncryptionContext) -> RekeyFactor {
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

// #[cfg(feature = "legacy-pep-repo-compatible")]
// TODO implement this function

// #[repr(u8)]
// enum PEPFactorType {
//     Pseudonymize = 0x01,
//     Rekey = 0x02,
// }

// CPP implementation that we should be binary compatible with.
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

