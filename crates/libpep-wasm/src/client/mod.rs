//! WASM bindings for the client module.

#[cfg(feature = "batch")]
pub mod batch;
pub mod distributed;
pub mod functions;
pub mod types;

pub use distributed::WASMClient;
#[cfg(feature = "offline")]
pub use types::WASMOfflinePEPClient;
