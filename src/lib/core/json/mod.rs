//! JSON value types that can be encrypted using PEP cryptography.
//!
//! This module provides `PEPJSONValue` which represents JSON values where
//! primitive values (bools, numbers, strings) are encrypted as Attributes
//! or LongAttributes, and optionally as Pseudonyms using `Pseudonym` variant.

pub mod builder;
pub mod core;
pub mod macros;
pub mod structure;
pub mod transcryption;
mod utils;
