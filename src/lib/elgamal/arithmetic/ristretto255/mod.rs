//! The ristretto255 group with SHA-512, ciphersuite `ristretto255-SHA512`.
//!
//! [`Ristretto255`] is the [`Group`](super::Group) instance, with the lizard encoding as its
//! [`InvertibleEncoding`](super::InvertibleEncoding). The concrete types live here too, since they
//! are ristretto255 and nothing else: [`group_elements`] has [`GroupElement`](group_elements::GroupElement)
//! and the base point [`G`](group_elements::G), [`scalars`] has [`ScalarNonZero`](scalars::ScalarNonZero)
//! and [`ScalarCanBeZero`](scalars::ScalarCanBeZero), and [`hashing`] has the raw-tag hash
//! functions.

mod group;
pub mod group_elements;
pub mod hashing;
pub mod scalars;

pub use group::Ristretto255;
