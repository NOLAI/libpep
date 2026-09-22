//! Transcryptor type definitions.
//!
//! The transcryptor is generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]; the name in this module is its ristretto255 instance.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`Transcryptor`](generic::Transcryptor) over ristretto255.
pub type Transcryptor = generic::Transcryptor<Ristretto255>;
