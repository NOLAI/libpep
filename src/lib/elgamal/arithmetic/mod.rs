//! Group arithmetic: the abstract prime-order [`Group`] the library is generic over, and its
//! ristretto255 instance.
//!
//! [`group`] defines the prime-order group API as a trait, together with the optional element
//! encodings. [`ristretto255`] instantiates it over Curve25519 with Ristretto, using the
//! [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) crate (with its `lizard`
//! feature for the lizard encoding). Its element and scalar types are [`GroupElement`](group_elements::GroupElement),
//! [`ScalarNonZero`](scalars::ScalarNonZero) and [`ScalarCanBeZero`](scalars::ScalarCanBeZero).
//!
//! Scalars can be converted into group elements by multiplying them with the base point
//! [`G`](group_elements::G). The two scalar types handle edge cases in the rest of the code where
//! a zero scalar is not allowed. The arithmetic operators for addition, subtraction and
//! multiplication are overloaded, so that the code matches the notation in the papers.

pub mod ciphersuite;
pub mod group;
pub mod hashing;
pub mod ristretto255;

pub use ciphersuite::Ciphersuite;
pub use group::{Bytes, Group, InvertibleEncoding, OaepEncoding};
pub use ristretto255::{group_elements, scalars, Ristretto255};
