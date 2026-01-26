//! PEP transcryptor system for pseudonymizing and rekeying encrypted data.

// Module declarations
#[cfg(feature = "batch")]
pub mod batch;
pub mod distributed;
pub mod functions;
pub mod prelude;
pub mod types;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export types
pub use types::Transcryptor;

// Re-export functions
pub use functions::{pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt};

// Re-export distributed types
pub use distributed::DistributedTranscryptor;

// Re-export batch functions and types
#[cfg(feature = "batch")]
pub use batch::{pseudonymize_batch, rekey_batch, transcrypt_batch, BatchError};
