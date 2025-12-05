pub mod core;
pub mod keys;
pub mod setup;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    let core_module = PyModule::new(py, "core")?;
    core::register(&core_module)?;
    m.add_submodule(&core_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.distributed.server.core", &core_module)?;

    let keys_module = PyModule::new(py, "keys")?;
    keys::register(&keys_module)?;
    m.add_submodule(&keys_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.distributed.server.keys", &keys_module)?;

    let setup_module = PyModule::new(py, "setup")?;
    setup::register(&setup_module)?;
    m.add_submodule(&setup_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.distributed.server.setup", &setup_module)?;

    Ok(())
}
