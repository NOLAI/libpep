//! Cryptographic factors for pseudonymization, rekeying and rerandomization, and their derivation
//! from secrets and [contexts](crate::contexts).
//!
//! A transcryptor holds a pseudonymization secret and a rekeying secret. It derives a reshuffle
//! factor for each pseudonymization domain and a rekey factor for each encryption context from
//! them, and these factors stay secret. With `n` distributed transcryptors, the factor that
//! is effectively applied is the product of the factors of all of them, so it stays secret as long
//! as one transcryptor keeps its factors secret.
//!
//! # Organization
//!
//! - [`types`]: Factor types (`ReshuffleFactor`, `PseudonymRekeyFactor`, `AttributeRekeyFactor`,
//!   `RerandomizeFactor`) and the info types that bundle the factors for one transcryption
//!   (`PseudonymizationInfo`, `PseudonymRekeyInfo`, `AttributeRekeyInfo`, `TranscryptionInfo`)
//! - [`secrets`]: Secret types (`PseudonymizationSecret`, `RekeyingSecret`) from which factors
//!   are derived
//! - [`derivation`]: Derivation of factors from secrets and contexts

pub mod derivation;
pub mod secrets;
pub mod types;

#[cfg(feature = "verifiable")]
pub mod commitments;
#[cfg(feature = "verifiable-derivation")]
pub mod verifiable;

pub use derivation::{
    make_attribute_rekey_factor, make_attribute_rekey_factor_generic, make_pseudonym_rekey_factor,
    make_pseudonym_rekey_factor_generic, make_pseudonymization_factor,
    make_pseudonymization_factor_generic,
};
pub use secrets::{PseudonymizationSecret, RekeyingSecret, Secret};
pub use types::{
    AttributeRekeyFactor, AttributeRekeyInfo, Factor, PseudonymRekeyFactor, PseudonymRekeyInfo,
    PseudonymizationInfo, RekeyPublicKey, RerandomizeFactor, ReshuffleFactor, TranscryptionInfo,
};

#[cfg(feature = "verifiable")]
pub use commitments::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
#[cfg(feature = "verifiable-derivation")]
pub use verifiable::{
    MasterPseudonymizationPublicKey, MasterPseudonymizationSecret, MasterRekeyingPublicKey,
    MasterRekeyingSecret,
};
