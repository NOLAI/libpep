//! Cryptographic factors and secrets for pseudonymization, rekeying, and rerandomization.
//!
//! This module provides:
//! - Secret types for storing pseudonymization and encryption secrets
//! - Factor types (ReshuffleFactor, RekeyFactor, RerandomizeFactor) for cryptographic operations
//! - Derivation functions for computing factors from secrets and contexts
//!
//! # Organization
//!
//! - [`contexts`]: Context types (PseudonymizationDomain, EncryptionContext)
//! - [`secrets`]: Secret types (PseudonymizationSecret, EncryptionSecret)
//! - [`types`]: Factor types and Info type aliases

pub mod contexts;
pub mod secrets;
pub mod types;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export commonly used types
pub use contexts::{EncryptionContext, PseudonymizationDomain};
pub use secrets::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
    EncryptionSecret, PseudonymizationSecret, Secret,
};
pub use types::{
    AttributeRekeyFactor, AttributeRekeyInfo, PseudonymRSKFactors, PseudonymRekeyFactor,
    PseudonymRekeyInfo, PseudonymizationInfo, RekeyFactor, RekeyInfoProvider, RerandomizeFactor,
    ReshuffleFactor, TranscryptionInfo,
};
