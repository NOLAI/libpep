//! JSON value types that can be encrypted using PEP cryptography.
//!
//! `PepJsonValue` represents a JSON value in which the primitive values (booleans, numbers,
//! strings) are encrypted as attributes or long attributes, and fields marked as pseudonyms are
//! encrypted as pseudonyms or long pseudonyms.

pub mod builder;
pub mod data;
pub mod encryption;
#[macro_use]
pub mod macros;
pub mod structure;
pub mod utils;

#[cfg(test)]
mod tests;

pub use builder::PepJsonBuilder;
pub use data::{EncryptedPepJsonValue, JsonError, PepJsonValue};
pub use structure::*;
