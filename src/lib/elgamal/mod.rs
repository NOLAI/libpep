//! ElGamal [encrypt]ion and [decrypt]ion, the underlying group [arithmetic], and the low-level
//! (n)-PEP [primitives] that operate on ElGamal ciphertexts.
//!
//! Use this module when the individual (n)-PEP primitives are needed. Most callers should use the
//! [high-level](crate::transcryptor) API, which also takes care of rerandomization.
//!
//! The ciphertext and the encryption functions are generic over the [`Group`](arithmetic::Group).

pub mod arithmetic;
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
