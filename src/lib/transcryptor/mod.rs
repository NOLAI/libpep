//! PEP transcryptor system for pseudonymizing and rekeying encrypted data.
//!
//! [`Transcryptor`] and [`DistributedTranscryptor`] are generic over the
//! [`Ciphersuite`](crate::elgamal::arithmetic::Ciphersuite), for example
//! `Transcryptor<Ristretto255Sha512>`, because they derive factors by hashing. The polymorphic
//! functions such as [`transcrypt`] take the group from their arguments and work for every type
//! of [`data`](crate::data).

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
