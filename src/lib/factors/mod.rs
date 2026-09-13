//! Cryptographic factors for pseudonymization, rekeying and rerandomization, and their derivation
//! from secrets and [contexts](crate::contexts).
//!
//! # Organization
//!
//! - [`types`]: Factor types (`ReshuffleFactor`, `PseudonymRekeyFactor`, `AttributeRekeyFactor`,
//!   `RerandomizeFactor`) and the info types that bundle the factors for one transcryption
//!   (`PseudonymizationInfo`, `PseudonymRekeyInfo`, `AttributeRekeyInfo`, `TranscryptionInfo`)
//! - [`secrets`]: Secret types (`PseudonymizationSecret`, `EncryptionSecret`) from which factors
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
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
};
pub use secrets::{EncryptionSecret, PseudonymizationSecret, Secret};
pub use types::{
    AttributeRekeyFactor, AttributeRekeyInfo, PseudonymRekeyFactor, PseudonymRekeyInfo,
    PseudonymizationInfo, RekeyFactor, RerandomizeFactor, ReshuffleFactor, TranscryptionInfo,
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
