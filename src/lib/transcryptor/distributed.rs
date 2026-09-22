//! Distributed transcryptor for generating session key shares.
//!
//! The distributed transcryptor is generic over the [`Group`](crate::elgamal::arithmetic::Group)
//! in [`generic`]; the name in this module is its ristretto255 instance.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`DistributedTranscryptor`](generic::DistributedTranscryptor) over ristretto255.
pub type DistributedTranscryptor = generic::DistributedTranscryptor<Ristretto255>;
