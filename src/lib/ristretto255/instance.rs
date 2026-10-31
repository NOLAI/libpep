//! The instantiation for ristretto255 with SHA-512.

use crate::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};

instantiate!(Ristretto255, Ristretto255Sha512);
