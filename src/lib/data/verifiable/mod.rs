//! Verifiable data-layer types.
//!
//! Mirrors the structure of [`crate::data`]: per data module (`simple`, `long`, `records`,
//! `json`) there is a matching module here with the proof types and the verifiable operations,
//! generic over the group in a `generic` submodule. The prover-side and verifier-side traits
//! live in [`traits`], and [`batch`] holds the batch proofs, which are generic over the item
//! type.

pub mod traits;

#[cfg(feature = "batch")]
pub mod batch;

pub mod simple;

#[cfg(feature = "long")]
pub mod long;

pub mod records;

#[cfg(feature = "json")]
pub mod json;
