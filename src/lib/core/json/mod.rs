//! JSON value types that can be encrypted using PEP cryptography.
//!
//! This module provides `PEPJSONValue` which represents JSON values where
//! primitive values (bools, numbers, strings) are encrypted as Attributes
//! or LongAttributes, and optionally as Pseudonyms using `Pseudonym` variant.

pub mod builder;
pub mod data;
pub mod macros;
#[cfg(feature = "offline")]
pub mod offline;
pub mod structure;
pub mod transcryption;
pub(crate) mod utils;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;
