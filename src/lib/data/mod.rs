//! The data types: pseudonyms, attributes, their long and encrypted forms, records, JSON
//! documents, and the traits the operations are generic over.
//!
//! # Where the ElGamal assumption lives
//!
//! Part of this module does not depend on how values are encrypted:
//!
//! - [`traits`] defines what it means to encrypt, rekey, pseudonymize and transcrypt a value,
//!   without naming a scheme.
//! - `batch` (with the `batch` feature) validates and shuffles batches through the structure of their items.
//! - `json::structure`, the JSON unification and the padding errors and external padding
//!   blocks work on shapes and byte strings.
//!
//! The rest is tied to a plaintext that is one group element and a ciphertext that is one
//! ElGamal ciphertext, and is where another scheme would plug in: [`elgamal`] (the two traits for
//! such blocks), [`simple`], `long`, [`records`], the JSON values in `json` and the
//! block encoding of [`padding`], and the proofs in `verifiable`.

#[cfg(feature = "batch")]
pub mod batch;
pub mod elgamal;
pub mod errors;
#[cfg(feature = "json")]
pub mod json;
#[cfg(feature = "long")]
pub mod long;
pub mod padding;
pub mod records;
pub mod simple;
pub mod traits;

#[cfg(feature = "verifiable")]
pub mod verifiable;
