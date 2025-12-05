#[allow(clippy::wrong_self_convention)]
pub mod data;
#[allow(clippy::wrong_self_convention)]
pub mod keys;
#[cfg(feature = "offline")]
pub mod offline;
pub mod padding;
pub mod rerandomize;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    let data_module = PyModule::new(py, "data")?;
    data::register(&data_module)?;
    m.add_submodule(&data_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.data", &data_module)?;

    let keys_module = PyModule::new(py, "keys")?;
    keys::register(&keys_module)?;
    m.add_submodule(&keys_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.keys", &keys_module)?;

    #[cfg(feature = "offline")]
    {
        let offline_module = PyModule::new(py, "offline")?;
        offline::register(&offline_module)?;
        m.add_submodule(&offline_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.core.offline", &offline_module)?;
    }

    let padding_module = PyModule::new(py, "padding")?;
    padding::register(&padding_module)?;
    m.add_submodule(&padding_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.padding", &padding_module)?;

    let rerandomize_module = PyModule::new(py, "rerandomize")?;
    rerandomize::register(&rerandomize_module)?;
    m.add_submodule(&rerandomize_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.rerandomize", &rerandomize_module)?;

    let transcryption_module = PyModule::new(py, "transcryption")?;
    super::transcryption::py::register_module(&transcryption_module)?;
    m.add_submodule(&transcryption_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.transcryption", &transcryption_module)?;

    #[cfg(feature = "long")]
    {
        let long_module = PyModule::new(py, "long")?;
        super::long::py::register_module(&long_module)?;
        m.add_submodule(&long_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.core.long", &long_module)?;
    }

    #[cfg(feature = "json")]
    {
        let json_module = PyModule::new(py, "json")?;
        super::json::py::register(&json_module)?;
        m.add_submodule(&json_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.core.json", &json_module)?;
    }

    Ok(())
}
