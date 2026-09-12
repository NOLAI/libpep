//! Distributed transcryptor key management.
//!
//! In a distributed setup the global secret keys are blinded with one blinding factor per
//! transcryptor, and each transcryptor contributes a session key share; a client combines the
//! blinded global secret key with all shares to obtain its session key. The material involved
//! is protocol state rather than keys, and has its own traits ([`BlindedGlobalSecretKey`],
//! [`SessionKeyShare`]) instead of [`SecretKey`](crate::keys::SecretKey).
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
