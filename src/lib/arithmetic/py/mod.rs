pub mod group_elements;
#[allow(clippy::wrong_self_convention)]
pub mod scalars;

pub use group_elements::PyGroupElement;
pub use scalars::{PyScalarCanBeZero, PyScalarNonZero};

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    scalars::register(m)?;
    group_elements::register(m)?;
    Ok(())
}
