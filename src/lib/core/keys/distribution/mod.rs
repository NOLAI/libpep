//! Distributed transcryptor key management.
//!
//! This module provides types and functions for managing keys in a distributed transcryptor system,
//! including blinding factors, session key shares, and key reconstruction.
//!
//! # Organization
//!
//! - [`blinding`]: Blinding factors and blinded global secret keys
//! - [`shares`]: Session key shares for transcryptors
//! - [`setup`]: System setup functions for creating distributed keys

pub mod blinding;
pub mod setup;
pub mod shares;

pub use blinding::{
    make_blinded_attribute_global_secret_key, make_blinded_global_keys,
    make_blinded_pseudonym_global_secret_key, BlindedAttributeGlobalSecretKey, BlindedGlobalKeys,
    BlindedPseudonymGlobalSecretKey, BlindingFactor,
};
pub use setup::{
    make_distributed_attribute_global_keys, make_distributed_global_keys,
    make_distributed_pseudonym_global_keys,
};
pub use shares::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_share,
    make_session_key_shares, AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
