//! PEP transcryptor system for pseudonymizing and rekeying encrypted data.
//!
//! [`Transcryptor`] and [`DistributedTranscryptor`] are generic over the
//! [`Group`](crate::elgamal::arithmetic::Group), for example `Transcryptor<Ristretto255>`, as are
//! the polymorphic functions such as [`transcrypt`], which work for every type of
//! [`data`](crate::data).

// Module declarations
#[cfg(feature = "batch")]
pub mod batch;
pub mod distributed;
pub mod functions;
pub mod prelude;
pub mod types;

#[cfg(feature = "verifiable")]
pub mod verifiable;

// Re-export types
pub use types::{Transcryptor, TranscryptorId};

// Re-export functions
pub use functions::{pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt};

// Re-export distributed types
pub use distributed::DistributedTranscryptor;

// Re-export batch functions and types
#[cfg(feature = "batch")]
pub use batch::{pseudonymize_batch, rekey_batch, transcrypt_batch};
