pub mod core;
#[cfg(feature = "global")]
pub mod global;
pub mod keys;

pub use core::PyPEPClient;
#[cfg(feature = "global")]
pub use global::PyOfflinePEPClient;
pub use keys::*;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    core::register(m)?;
    keys::register(m)?;
    #[cfg(feature = "global")]
    global::register(m)?;
    Ok(())
}
