//! High-level API specifying [Pseudonyms](data_types::Pseudonym) and [Attributes](data_types::Attribute),
//! and [transcryption](ops::transcrypt) ([pseudonymization](ops::pseudonymize) or [rekeying](ops::rekey))
//! of their encrypted versions between different contexts.
//! This module is intended for most use cases where a *single* trusted party (transcryptor) is
//! responsible for pseudonymization and rekeying.
//! The API is designed to be user-friendly and safe.

pub mod contexts;
pub mod data_types;
pub mod keys;
pub mod ops;
pub mod padding;
pub mod secrets;
