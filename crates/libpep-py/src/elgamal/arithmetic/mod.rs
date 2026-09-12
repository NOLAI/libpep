pub mod group_elements;
#[allow(clippy::wrong_self_convention)]
pub mod scalars;

// Re-export for internal Rust use
pub(crate) use group_elements::PyGroupElement;
pub(crate) use scalars::PyScalarNonZero;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::add_submodule(m, "libpep.elgamal.arithmetic.scalars", |sm| {
        scalars::register(sm)
    })?;
    crate::add_submodule(m, "libpep.elgamal.arithmetic.group_elements", |sm| {
        group_elements::register(sm)
    })?;
    Ok(())
}
