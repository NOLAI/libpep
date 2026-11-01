//! PEP transcryptor system for pseudonymizing and rekeying encrypted data.
//!
//! [`Transcryptor`] and [`DistributedTranscryptor`] derive factors from their secrets. The
//! polymorphic functions such as [`transcrypt`] work for every type of [`data`](crate::data).
//!
//! A transcryptor works blindly, on encrypted data only. *Pseudonymization* reshuffles and rekeys
//! an encrypted pseudonym, converting it from the pseudonymization domain and encryption context
//! of one user to those of another; *rekeying* only changes the key an encrypted value
//! (an attribute) can be decrypted with. *Transcryption* is the joint operation: pseudonymization
//! for pseudonyms and rekeying for attributes. The operations rerandomize their input first, which
//! protects against a sender that injects a plaintext pseudonym instead of a ciphertext (this
//! holds as long as at least one transcryptor rerandomizes honestly).
//!
//! A transcryption request reveals the authenticated requesting user and the source and target
//! domains and contexts, but not the values of pseudonyms or data, so a transcryptor can decide
//! whether the conversion between two users is allowed. With `n` distributed transcryptors, each
//! applies its own factors in turn and each can independently block a transcryption.
//!
//! The scheme guarantees confidentiality and pseudonym unlinkability, but not integrity: unless
//! the proofs of the `verifiable` feature are verified, a transcryptor could return a corrupted
//! ciphertext, or apply inconsistent factors, unnoticed.

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
