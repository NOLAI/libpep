//! Implementation of arithmetic operations on Curve25519 with Ristretto, using the
//! `curve25519-dalek` library.
//!
//! We use the [`signalapp/curve25519-dalek`](https://github.com/signalapp/curve25519-dalek)
//! fork of the well-known [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek)
//! crate (which we published as [`curve25519-dalek-libpep`](https://crates.io/crates/curve25519-dalek-libpep)),
//! to use lizard encoding and decoding for [`GroupElement`]s.
//!
//! Scalars can be converted into [`GroupElement`]s by multiplying them with the base point [`G`].
//!
//! We define two types of scalars: [`ScalarNonZero`] and [`ScalarCanBeZero`] to nicely handle edge
//! cases in the rest of the code where a zero scalar is not allowed.
//! Moreover, we overload the arithmetic operators for addition, subtraction, and multiplication,
//! so that the code is more readable and easier to understand, so it matches the notation in the
//! mathematical papers.

pub mod group_elements;
pub mod ops;
pub mod scalars;

#[cfg(feature = "python")]
pub mod py;

#[cfg(feature = "wasm")]
pub mod wasm;
