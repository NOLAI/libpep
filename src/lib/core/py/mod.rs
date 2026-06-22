pub mod elgamal;
pub mod primitives;

#[cfg(feature = "verifiable")]
pub mod verifiable;

#[cfg(feature = "verifiable")]
pub mod zkps;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    let elgamal_module = PyModule::new(py, "elgamal")?;
    elgamal::register(&elgamal_module)?;
    m.add_submodule(&elgamal_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.elgamal", &elgamal_module)?;

    let primitives_module = PyModule::new(py, "primitives")?;
    primitives::register(&primitives_module)?;
    m.add_submodule(&primitives_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.primitives", &primitives_module)?;

    #[cfg(feature = "verifiable")]
    {
        let zkps_module = PyModule::new(py, "zkps")?;
        zkps::register(&zkps_module)?;
        m.add_submodule(&zkps_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.core.zkps", &zkps_module)?;

        // Registers `libpep.core.verifiable` as a proper submodule.
        verifiable::register_module(m)?;
    }

    Ok(())
}
