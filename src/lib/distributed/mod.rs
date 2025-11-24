//! Distributed n-PEP with wrappers for high-level [`PEPSystems`](server::core::PEPSystem) (*transcryptors*) and [`PEPClients`](client::core::PEPClient).
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
        crate::distributed::client::py::register_module(m)?;
        crate::distributed::server::py::register_module(m)?;
        Ok(())
    }
}
