pub mod ciphersuite;
pub mod hashing;
pub mod ristretto255;

// Re-export for internal Rust use
pub(crate) use group_elements::PyGroupElement;
pub use ristretto255::{group_elements, scalars};
pub(crate) use scalars::PyScalarNonZero;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::add_submodule(m, "libpep.elgamal.arithmetic.scalars", |sm| {
        scalars::register(sm)
    })?;
    crate::add_submodule(m, "libpep.elgamal.arithmetic.group_elements", |sm| {
        group_elements::register(sm)
    })?;
    crate::add_submodule(m, "libpep.elgamal.arithmetic.hashing", |sm| {
        hashing::register(sm)
    })?;
    crate::add_submodule(m, "libpep.elgamal.arithmetic.ciphersuite", |sm| {
        ciphersuite::register(sm)
    })?;
    Ok(())
}
