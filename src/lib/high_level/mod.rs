//! High-level API specifying [Pseudonyms](core::Pseudonym) and [Attributes](core::Attribute),
//! and [transcryption](transcryption::ops::transcrypt) ([pseudonymization](transcryption::ops::pseudonymize) or [rekeying](transcryption::ops::rekey))
//! of their encrypted versions between different contexts.
//! This module is intended for most use cases where a *single* trusted party (transcryptor) is
//! responsible for pseudonymization and rekeying.
//! The API is designed to be user-friendly and safe.

pub mod core;
#[cfg(feature = "global")]
pub mod global;
pub mod keys;
#[cfg(feature = "long")]
pub mod long;
pub mod padding;
pub mod rerandomize;
pub mod transcryption;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;
