//! Python bindings for libpep.
//!
//! This module re-exports Python bindings from their respective submodules.

// Re-export from submodules
pub use crate::arithmetic::py as arithmetic;
pub use crate::client::py as client;
pub use crate::core::py as core;
pub use crate::data::py as data;
pub use crate::factors::py as factors;
pub use crate::keys::py as keys;
pub use crate::transcryptor::py as transcryptor;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // Register arithmetic as submodule
    let arithmetic_module = PyModule::new(py, "arithmetic")?;
    arithmetic::register_module(&arithmetic_module)?;
    m.add_submodule(&arithmetic_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.arithmetic", &arithmetic_module)?;

    // Register core as submodule
    let core_module = PyModule::new(py, "core")?;
    core::register_module(&core_module)?;
    m.add_submodule(&core_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core", &core_module)?;

    // Register client as submodule
    let client_module = PyModule::new(py, "client")?;
    client::types::register(&client_module)?;
    client::distributed::register(&client_module)?;
    client::functions::register(&client_module)?;
    #[cfg(feature = "batch")]
    client::batch::register(&client_module)?;
    m.add_submodule(&client_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.client", &client_module)?;

    // Register transcryptor as submodule
    let transcryptor_module = PyModule::new(py, "transcryptor")?;
    transcryptor::types::register(&transcryptor_module)?;
    transcryptor::distributed::register(&transcryptor_module)?;
    transcryptor::functions::register(&transcryptor_module)?;
    #[cfg(feature = "batch")]
    transcryptor::batch::register(&transcryptor_module)?;
    m.add_submodule(&transcryptor_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.transcryptor", &transcryptor_module)?;

    // Register keys as submodule
    let keys_module = PyModule::new(py, "keys")?;
    keys::register(&keys_module)?;
    m.add_submodule(&keys_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.keys", &keys_module)?;

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
        .set_item("libpep.data", &data_module)?;

    // Register json as a separate submodule under data
    #[cfg(feature = "json")]
    {
        let json_module = PyModule::new(py, "json")?;
        data::json::register(&json_module)?;
        data_module.add_submodule(&json_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.data.json", &json_module)?;
    }

    // Register factors as submodule
    let factors_module = PyModule::new(py, "factors")?;
    factors::contexts::register(&factors_module)?;
    factors::types::register(&factors_module)?;
    factors::secrets::register(&factors_module)?;
    m.add_submodule(&factors_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.factors", &factors_module)?;

    Ok(())
}
