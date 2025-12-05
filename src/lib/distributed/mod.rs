//! Distributed n-PEP with wrappers for high-level [`PEPSystems`](server::transcryptor::PEPSystem) (*transcryptors*) and [`PEPClients`](client::client::PEPClient).
//! This module is intended for use cases where transcryption is performed by *n* parties and
//! trust is distributed among them (i.e. no single party is trusted but the system remains secure
//! as long as at least 1 party remains honest).

pub mod client;
pub mod server;

#[cfg(feature = "python")]
pub mod py {
    //! Python bindings for the distributed module.

    use pyo3::prelude::*;

    pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
        let py = m.py();

        // Create submodules to mirror Rust structure
        let client_module = PyModule::new(py, "client")?;
        crate::distributed::client::py::register_module(&client_module)?;
        m.add_submodule(&client_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.distributed.client", &client_module)?;

        let server_module = PyModule::new(py, "server")?;
        crate::distributed::server::py::register_module(&server_module)?;
        m.add_submodule(&server_module)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item("libpep.distributed.server", &server_module)?;

        Ok(())
    }
}
