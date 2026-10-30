//! Python bindings for the verifier.

mod verify;

pub use verify::PyVerifier;

use pyo3::prelude::*;

#[allow(dead_code)]
pub(crate) fn register_verifier_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<PyVerifier>()?;
    Ok(())
}
