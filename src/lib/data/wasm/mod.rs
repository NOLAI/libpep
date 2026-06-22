//! WASM bindings for PEP data types.

pub mod simple;

#[cfg(feature = "batch")]
pub mod batch;

#[cfg(all(feature = "batch", feature = "verifiable"))]
pub mod verifiable_batch;

#[cfg(feature = "json")]
pub mod json;

#[cfg(all(feature = "json", feature = "verifiable"))]
pub mod verifiable_json;

#[cfg(feature = "long")]
pub mod long;

pub mod padding;

pub mod records;

// Re-export simple types at data level for backwards compatibility
pub use simple::*;
