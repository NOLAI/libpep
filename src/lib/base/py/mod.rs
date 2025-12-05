pub mod elgamal;
pub mod primitives;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    let elgamal_module = PyModule::new(py, "elgamal")?;
    elgamal::register(&elgamal_module)?;
    m.add_submodule(&elgamal_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.base.elgamal", &elgamal_module)?;

    let primitives_module = PyModule::new(py, "primitives")?;
    primitives::register(&primitives_module)?;
    m.add_submodule(&primitives_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.base.primitives", &primitives_module)?;

    Ok(())
}
