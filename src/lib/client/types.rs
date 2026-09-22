//! Client type definitions.
//!
//! The clients are generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]; the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`Client`](generic::Client) over ristretto255.
pub type Client = generic::Client<Ristretto255>;
/// The [`OfflineClient`](generic::OfflineClient) over ristretto255.
#[cfg(feature = "offline")]
pub type OfflineClient = generic::OfflineClient<Ristretto255>;
