//! High-level API specifying [Pseudonyms](data::simple::Pseudonym) and [Attributes](data::simple::Attribute),
//! and [transcryption](functions::transcrypt) ([pseudonymization](functions::pseudonymize) or [rekeying](functions::rekey))
//! of their encrypted versions between different contexts.
//! This module is intended for most use cases where a *single* trusted party (transcryptor) is
//! responsible for pseudonymization and rekeying.
//! The API is designed to be user-friendly and safe.

#[cfg(feature = "batch")]
pub mod batch;
pub mod client;
pub mod contexts;
pub mod data;
pub mod factors;
pub mod functions;
pub mod keys;
pub mod transcryptor;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;
