//! JSON value types that can be encrypted using PEP cryptography.
//!
//! This module provides `PEPJSONValue` which represents JSON values where
//! primitive values (bools, numbers, strings) are encrypted as Attributes
//! or LongAttributes, and optionally as Pseudonyms using `Pseudonym` variant.

pub mod builder;
pub mod data;
#[macro_use]
pub mod macros;
pub mod structure;
pub(crate) mod utils;

// Re-export public types
pub use builder::*;
pub use data::*;
pub use structure::*;
