//! PEP client for encrypting and decrypting data using session keys or global public keys.

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
pub use types::Client;
#[cfg(feature = "offline")]
pub use types::OfflineClient;

// Re-export functions
pub use functions::{decrypt, encrypt};

#[cfg(feature = "offline")]
pub use functions::encrypt_global;

#[cfg(all(feature = "offline", feature = "insecure"))]
pub use functions::decrypt_global;

// Re-export distributed trait
pub use distributed::Distributed;

// Re-export batch functions
#[cfg(feature = "batch")]
pub use batch::{decrypt_batch, encrypt_batch};

#[cfg(all(feature = "batch", feature = "offline"))]
pub use batch::encrypt_global_batch;

#[cfg(all(feature = "batch", feature = "offline", feature = "insecure"))]
pub use batch::decrypt_global_batch;
