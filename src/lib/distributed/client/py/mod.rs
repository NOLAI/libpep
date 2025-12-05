pub mod core;
pub mod keys;
#[cfg(feature = "offline")]
pub mod offline;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    let core_module = PyModule::new(py, "core")?;
    core::register(&core_module)?;
    m.add_submodule(&core_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.distributed.client.core", &core_module)?;

    let keys_module = PyModule::new(py, "keys")?;
    keys::register(&keys_module)?;
    m.add_submodule(&keys_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.distributed.client.keys", &keys_module)?;

    #[cfg(feature = "offline")]
    {
        let offline_module = PyModule::new(py, "offline")?;
        offline::register(&offline_module)?;
        m.add_submodule(&offline_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.distributed.client.offline", &offline_module)?;
    }

    Ok(())
}
