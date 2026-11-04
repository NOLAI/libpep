//! The ristretto255 group.
//!
//! [`Ristretto255`] is the [`Group`](super::Group) instance, with the lizard encoding as its
//! [`InvertibleEncoding`](super::InvertibleEncoding). The concrete types live here too, since they
//! are ristretto255 and nothing else: [`elements`] has [`GroupElement`](elements::GroupElement)
//! and the base point [`G`](elements::G), and [`scalars`] has [`ScalarNonZero`](scalars::ScalarNonZero)
//! and [`ScalarCanBeZero`](scalars::ScalarCanBeZero). The ciphersuite that pairs the group with
//! SHA-512 is [`Ristretto255Sha512`](crate::ciphersuite::Ristretto255Sha512).

pub mod elements;
mod group;
pub mod scalars;

pub use group::Ristretto255;
