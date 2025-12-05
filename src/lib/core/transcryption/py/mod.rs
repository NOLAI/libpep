#[cfg(feature = "batch")]
pub mod batch;
pub mod contexts;
pub mod ops;
pub mod secrets;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // Create submodules to mirror Rust structure
    #[cfg(feature = "batch")]
    {
        let batch_module = PyModule::new(py, "batch")?;
        batch::register(&batch_module)?;
        m.add_submodule(&batch_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.core.transcryption.batch", &batch_module)?;
    }

    let contexts_module = PyModule::new(py, "contexts")?;
    contexts::register(&contexts_module)?;
    m.add_submodule(&contexts_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.transcryption.contexts", &contexts_module)?;

    let ops_module = PyModule::new(py, "ops")?;
    ops::register(&ops_module)?;
    m.add_submodule(&ops_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.transcryption.ops", &ops_module)?;

    let secrets_module = PyModule::new(py, "secrets")?;
    secrets::register(&secrets_module)?;
    m.add_submodule(&secrets_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.transcryption.secrets", &secrets_module)?;

    Ok(())
}
