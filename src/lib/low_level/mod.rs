//! Low-level cryptographic [primitives] for [ElGamal](elgamal) encryption and (n)-PEP operations.
//! This module is intended for non-standard uses cases where the individual (n)-PEP primitives are
//! needed.
//!
//! For most use cases, the [high-level](crate::high_level) API should be used, which provides
//! a more user-friendly and safer interface.

pub mod elgamal;
pub mod primitives;
