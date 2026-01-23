#[cfg(feature = "batch")]
pub mod batch;
#[allow(clippy::wrong_self_convention)]
pub mod client;
pub mod contexts;
#[allow(clippy::wrong_self_convention)]
pub mod data;
pub mod factors;
pub mod functions;
#[allow(clippy::wrong_self_convention)]
pub mod keys;
#[allow(clippy::wrong_self_convention)]
pub mod transcryptor;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // Register client
    client::register(m)?;

    // Register transcryptor
    transcryptor::register(m)?;

    // Register contexts
    contexts::register(m)?;

    // Register functions
    functions::register(m)?;

    // Register batch
    #[cfg(feature = "batch")]
    batch::register(m)?;

    // Register keys as submodule
    let keys_module = PyModule::new(py, "keys")?;
    keys::register(&keys_module)?;
    m.add_submodule(&keys_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.keys", &keys_module)?;

    // Register data as submodule
    let data_module = PyModule::new(py, "data")?;
    data::simple::register(&data_module)?;
    #[cfg(feature = "long")]
    data::long::register(&data_module)?;
    data::padding::register(&data_module)?;
    data::records::register(&data_module)?;
    m.add_submodule(&data_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.data", &data_module)?;

    // Register json as a separate submodule under data
    #[cfg(feature = "json")]
    {
        let json_module = PyModule::new(py, "json")?;
        data::json::register(&json_module)?;
        data_module.add_submodule(&json_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.core.data.json", &json_module)?;
    }

    // Register factors as submodule
    let factors_module = PyModule::new(py, "factors")?;
    factors::types::register(&factors_module)?;
    factors::secrets::register(&factors_module)?;
    m.add_submodule(&factors_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.factors", &factors_module)?;

    Ok(())
}
