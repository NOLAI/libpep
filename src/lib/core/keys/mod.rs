//! Key management for PEP encryption.
//!
//! This module provides types and functions for managing global keys (used for system configuration),
//! session keys (used for encryption/decryption), and distributed transcryptor key management.
//!
//! Keys are split into separate Attribute and Pseudonym encryption keys to prevent pseudonym values
//! from being leaked by falsely presenting them as attributes.
//!
//! # Organization
//!
//! - [`types`]: Key type definitions for global and session keys
//! - [`traits`]: Traits for public and secret keys
//! - [`generation`]: Functions for generating global and session keys
//! - [`distribution`]: Distributed transcryptor key management (blinding, shares, setup)

pub mod distribution;
pub mod generation;
pub mod traits;
pub mod types;

// Re-export commonly used types
pub use generation::*;
pub use traits::*;
pub use types::*;
