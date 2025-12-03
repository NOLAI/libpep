pub mod core;
pub mod keys;
pub mod setup;

pub use core::PyPEPSystem;
pub use keys::{
    py_make_attribute_session_key_share, py_make_pseudonym_session_key_share,
    py_make_session_key_shares,
};
pub use setup::{
    py_make_blinded_attribute_global_secret_key, py_make_blinded_global_keys,
    py_make_blinded_pseudonym_global_secret_key, py_make_distributed_attribute_global_keys,
    py_make_distributed_global_keys, py_make_distributed_pseudonym_global_keys,
    PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalKeys, PyBlindedPseudonymGlobalSecretKey,
    PyBlindingFactor,
};

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    core::register(m)?;
    keys::register(m)?;
    setup::register(m)?;
    #[cfg(feature = "json")]
    super::json::py::register(m)?;
    Ok(())
}
