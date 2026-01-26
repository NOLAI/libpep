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

pub use blinding::*;
pub use setup::*;
pub use shares::*;
