//! Python bindings for [libpep](https://crates.io/crates/libpep), built with PyO3 and distributed on PyPI as `libpep-py`
//! (importable as `libpep`).

pub(crate) mod macros;

pub mod client;
pub mod contexts;
pub mod data;
pub mod elgamal;
pub mod factors;
pub mod keys;
pub mod transcryptor;

#[cfg(feature = "verifiable")]
pub mod verifier;

pub mod errors;

use pyo3::prelude::*;

/// Creates a named submodule, runs the given registration closure on it, attaches it to the
/// parent, and patches `sys.modules` so `import libpep.<name>` works.
pub(crate) fn add_submodule<'py>(
    parent: &Bound<'py, PyModule>,
    path: &str,
    fill: impl FnOnce(&Bound<'py, PyModule>) -> PyResult<()>,
) -> PyResult<Bound<'py, PyModule>> {
    let py = parent.py();
    let name = path.rsplit('.').next().unwrap_or(path);
    let module = PyModule::new(py, name)?;
    fill(&module)?;
    parent.add_submodule(&module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item(path, &module)?;
    Ok(module)
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    errors::register(m)?;
    add_submodule(m, "libpep.elgamal", |sm| elgamal::register_module(sm))?;
    add_submodule(m, "libpep.client", |sm| {
        client::types::register(sm)?;
        client::distributed::register(sm)?;
        client::functions::register(sm)?;
        #[cfg(feature = "batch")]
        client::batch::register(sm)?;
        Ok(())
    })?;
    add_submodule(m, "libpep.transcryptor", |sm| {
        transcryptor::types::register(sm)?;
        transcryptor::distributed::register(sm)?;
        transcryptor::functions::register(sm)?;
        #[cfg(feature = "batch")]
        transcryptor::batch::register(sm)?;
        Ok(())
    })?;
    add_submodule(m, "libpep.keys", |sm| keys::register(sm))?;
    let data_module = add_submodule(m, "libpep.data", |sm| {
        data::simple::register(sm)?;
        #[cfg(feature = "long")]
        data::long::register(sm)?;
        data::padding::register(sm)?;
        data::records::register(sm)?;
        #[cfg(feature = "batch")]
        data::batch::register(sm)?;
        #[cfg(all(feature = "batch", feature = "verifiable"))]
        data::verifiable_batch::register(sm)?;
        Ok(())
    })?;
    #[cfg(feature = "json")]
    add_submodule(&data_module, "libpep.data.json", |sm| {
        data::json::register(sm)?;
        #[cfg(feature = "verifiable")]
        data::verifiable_json::register(sm)?;
        Ok(())
    })?;
    #[cfg(not(feature = "json"))]
    drop(data_module);
    add_submodule(m, "libpep.contexts", |sm| contexts::register(sm))?;
    add_submodule(m, "libpep.factors", |sm| factors::register(sm))?;
    #[cfg(feature = "verifiable")]
    add_submodule(m, "libpep.verifier", |sm| {
        verifier::register_verifier_module(sm)
    })?;
    Ok(())
}

/// Python module for libpep.
#[pymodule]
fn libpep(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_module(m)
}
