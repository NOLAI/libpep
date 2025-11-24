//! Python bindings for libpep using PyO3.

// PyO3 code triggers clippy warnings that don't apply to Python bindings
#![allow(clippy::useless_conversion, clippy::wrong_self_convention)]

use pyo3::prelude::*;

/// Python module for libpep.
#[pymodule]
pub fn libpep(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    let modules = [
        (
            "arithmetic",
            crate::arithmetic::py::register_module as fn(&Bound<'_, PyModule>) -> PyResult<()>,
        ),
        ("base", crate::base::py::register_module),
        ("core", crate::core::py::register_module),
        ("distributed", crate::distributed::py::register_module),
    ];

    for (name, register_fn) in modules {
        let submodule = PyModule::new(py, name)?;
        register_fn(&submodule)?;
        m.add_submodule(&submodule)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item(format!("libpep.{}", name), &submodule)?;
    }

    Ok(())
}
