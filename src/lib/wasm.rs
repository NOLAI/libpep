//! WASM bindings for libpep.
//!
//! This module re-exports WASM bindings from their respective submodules.

// Re-export from submodules
pub use crate::client::wasm as client;
pub use crate::core::wasm as core;
pub use crate::data::wasm as data;
pub use crate::factors::wasm as factors;
pub use crate::keys::wasm as keys;
pub use crate::transcryptor::wasm as transcryptor;

#[cfg(feature = "verifiable")]
pub use crate::verifier::wasm as verifier;
