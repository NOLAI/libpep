//! Long (multi-block) data types and operations.
//!
//! This module provides support for multi-block pseudonyms and attributes that can hold
//! more than 16 bytes of data, along with all cryptographic operations for these types.

#[cfg(feature = "batch")]
pub mod batch;
pub mod data;
#[cfg(feature = "offline")]
pub mod offline;
pub mod ops;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;
