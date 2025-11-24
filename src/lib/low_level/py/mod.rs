pub mod elgamal;
pub mod primitives;

pub use elgamal::PyElGamal;
pub use primitives::*;

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    elgamal::register(m)?;
    primitives::register(m)?;
    Ok(())
}
