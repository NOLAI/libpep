//! PEP transcryptor system for pseudonymizing and rekeying encrypted data.
//!
//! # Per-message vs batch operations
//!
//! - **Per-message** — [`Transcryptor`]'s `rekey`, `pseudonymize`,
//!   `transcrypt`, and the `verifiable_*` variants take a single encrypted
//!   value and return either the new value (non-verifiable) or a proof
//!   (verifiable). They are polymorphic over any encrypted type implementing
//!   the matching trait (simple, long, records, JSON).
//! - **Batch (non-verifiable)** — the batch operations
//!   `pseudonymize`/`rekey`/`transcrypt` live as inherent methods on
//!   [`EncryptedBatch<E>`](crate::data::batch::EncryptedBatch), one impl per
//!   concrete `E`. Each mutates the batch in place, shuffles the items, and
//!   (under `elgamal2`) converts the stored recipient public key with the
//!   corresponding rekey factor.
//! - **Batch (verifiable)** — also inherent methods on each concrete batch
//!   type, returning type-specific proofs (`VerifiableRRSKBatch`,
//!   `VerifiableRekeyBatch`, `VerifiableRecordBatch`, …). Call them directly
//!   on the batch.

// Module declarations
#[cfg(feature = "batch")]
pub mod batch;
pub mod distributed;
pub mod functions;
pub mod prelude;
pub mod types;

#[cfg(feature = "verifiable")]
pub mod verifiable;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export types
pub use types::{Transcryptor, TranscryptorId};

// Re-export functions
pub use functions::{pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt};

// Re-export distributed types
pub use distributed::DistributedTranscryptor;

// Re-export batch error type for backwards compatibility. The batch
// operations themselves live as methods on
// [`EncryptedBatch`](crate::data::batch::EncryptedBatch).
#[cfg(feature = "batch")]
pub use crate::data::batch::BatchError;
