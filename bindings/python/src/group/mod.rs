//! Python bindings for the ristretto255 group: its elements and scalars.

pub mod elements;
#[allow(clippy::wrong_self_convention)]
pub mod scalars;

// Re-export for internal Rust use
pub(crate) use elements::PyGroupElement;
pub(crate) use scalars::PyScalarNonZero;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::add_submodule(m, "libpep.group.scalars", |sm| scalars::register(sm))?;
    crate::add_submodule(m, "libpep.group.elements", |sm| elements::register(sm))?;
    Ok(())
}
