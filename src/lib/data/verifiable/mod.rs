//! Verifiable data-layer types.
//!
//! Mirrors the structure of [`crate::data`]: per non-verifiable module
//! (`simple`, `long`, `records`, `json`) there is a matching verifiable
//! module here that contains the proof types and the verifiable-operation
//! impls. Verifier-side and prover-side traits live in [`traits`].

pub mod traits;

pub mod simple;

#[cfg(feature = "long")]
pub mod long;

pub mod records;

#[cfg(feature = "json")]
pub mod json;
