pub mod arithmetic;
pub mod ciphertext;
pub mod primitives;

#[cfg(feature = "verifiable")]
pub mod verifiable;
#[cfg(feature = "verifiable")]
pub mod zkps;

pub use ciphertext::{decrypt_py, encrypt_py, PyElGamal};

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    ciphertext::register(m)?;
    crate::add_submodule(m, "libpep.elgamal.arithmetic", |sm| {
        arithmetic::register_module(sm)
    })?;
    crate::add_submodule(m, "libpep.elgamal.primitives", |sm| {
        primitives::register(sm)
    })?;
    #[cfg(feature = "verifiable")]
    crate::add_submodule(m, "libpep.elgamal.zkps", |sm| zkps::register(sm))?;
    #[cfg(feature = "verifiable")]
    verifiable::register_module(m)?;
    Ok(())
}
