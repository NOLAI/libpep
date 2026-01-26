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

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export commonly used types
pub use generation::{
    make_attribute_global_keys, make_attribute_session_keys, make_global_key_pair,
    make_global_keys, make_pseudonym_global_keys, make_pseudonym_session_keys,
    make_session_key_pair, make_session_keys,
};
pub use traits::{KeyProvider, PublicKey, SecretKey};
pub use types::{
    AttributeGlobalPublicKey, AttributeGlobalSecretKey, AttributeSessionKeys,
    AttributeSessionPublicKey, AttributeSessionSecretKey, GlobalPublicKeys, GlobalSecretKeys,
    PseudonymGlobalPublicKey, PseudonymGlobalSecretKey, PseudonymSessionKeys,
    PseudonymSessionPublicKey, PseudonymSessionSecretKey, SessionKeys,
};
