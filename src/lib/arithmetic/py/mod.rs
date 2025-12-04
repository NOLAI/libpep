pub mod group_elements;
#[allow(clippy::wrong_self_convention)]
pub mod scalars;

// Re-export for internal Rust use
pub(crate) use group_elements::PyGroupElement;
pub(crate) use scalars::PyScalarNonZero;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    let scalars_module = PyModule::new(py, "scalars")?;
    scalars::register(&scalars_module)?;
    m.add_submodule(&scalars_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.arithmetic.scalars", &scalars_module)?;

    let group_elements_module = PyModule::new(py, "group_elements")?;
    group_elements::register(&group_elements_module)?;
    m.add_submodule(&group_elements_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.arithmetic.group_elements", &group_elements_module)?;

    Ok(())
}
