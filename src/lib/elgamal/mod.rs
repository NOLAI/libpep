//! ElGamal [encrypt]ion and [decrypt]ion over a [`Group`](crate::group::Group), and the
//! low-level (n)-PEP [primitives] that operate on ElGamal ciphertexts.
//!
//! Use this module when the individual (n)-PEP primitives are needed. Most callers should use the
//! [high-level](crate::transcryptor) API, which also takes care of rerandomization.

mod ciphertext;
pub mod primitives;
#[cfg(test)]
mod test_util;

#[cfg(feature = "verifiable")]
pub mod dleq;
#[cfg(feature = "verifiable")]
/// The verifiable primitives: every operation with a zero-knowledge proof of its correct
/// application (`verifiable` feature).
pub mod verifiable;
#[cfg(feature = "verifiable")]
pub mod zkps;

pub use ciphertext::{decrypt, encrypt, ElGamal};
