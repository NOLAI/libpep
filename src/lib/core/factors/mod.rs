//! Cryptographic factors and secrets for pseudonymization, rekeying, and rerandomization.
//!
//! This module provides:
//! - Secret types for storing pseudonymization and encryption secrets
//! - Factor types (ReshuffleFactor, RekeyFactor, RerandomizeFactor) for cryptographic operations
//! - Derivation functions for computing factors from secrets and contexts
//!
//! # Organization
//!
//! - [`secrets`]: Secret types (PseudonymizationSecret, EncryptionSecret)
//! - [`types`]: Factor types and Info type aliases
//! - [`derivation`]: Functions for deriving factors from contexts and secrets

pub mod derivation;
pub mod secrets;
pub mod types;

// Re-export commonly used types
pub use derivation::*;
pub use secrets::*;
pub use types::*;
