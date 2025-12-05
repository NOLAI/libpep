pub mod batch;
pub mod data;
#[cfg(feature = "offline")]
pub mod offline;
pub mod ops;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // Create submodules to mirror Rust structure
    let batch_module = PyModule::new(py, "batch")?;
    batch::register(&batch_module)?;
    m.add_submodule(&batch_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.long.batch", &batch_module)?;

    let data_module = PyModule::new(py, "data")?;
    data::register(&data_module)?;
    m.add_submodule(&data_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.long.data", &data_module)?;

    #[cfg(feature = "offline")]
    {
        let offline_module = PyModule::new(py, "offline")?;
        offline::register(&offline_module)?;
        m.add_submodule(&offline_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.core.long.offline", &offline_module)?;
    }

    let ops_module = PyModule::new(py, "ops")?;
    ops::register(&ops_module)?;
    m.add_submodule(&ops_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.long.ops", &ops_module)?;

    Ok(())
}
