//! WASM bindings for libpep.
//!
//! This module re-exports WASM bindings from their respective submodules.

// Re-export from submodules
pub use crate::client::wasm as client;
pub use crate::data::wasm as data;
pub use crate::factors::wasm as factors;
pub use crate::keys::wasm as keys;
pub use crate::transcryptor::wasm as transcryptor;

// Re-export functions from client module for backwards compatibility
pub use client::functions::*;
