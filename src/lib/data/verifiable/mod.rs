//! Verifiable data-layer types.
//!
//! Mirrors the structure of [`crate::data`]: per data module (`simple`, `long`, `records`,
//! `json`) there is a matching module here with the proof types and the verifiable operations.
//! The prover-side and verifier-side traits live in [`traits`], and [`batch`] holds the batch
//! proofs, which are generic over the item type.

#[cfg(feature = "batch")]
pub mod batch;
#[cfg(all(feature = "elgamal3", any(feature = "batch", feature = "long")))]
mod common;
pub mod traits;

pub mod simple;

#[cfg(feature = "long")]
pub mod long;

pub mod records;

#[cfg(feature = "json")]
pub mod json;
