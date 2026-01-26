//! Python bindings for distributed transcryptor key management.

pub mod blinding;
pub mod setup;
pub mod shares;

pub use blinding::{
    PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalKeys, PyBlindedPseudonymGlobalSecretKey,
    PyBlindingFactor,
};
pub use setup::{
    py_make_distributed_attribute_global_keys, py_make_distributed_global_keys,
    py_make_distributed_pseudonym_global_keys,
};
pub use shares::{
    py_make_attribute_session_key_share, py_make_pseudonym_session_key_share,
    py_make_session_key_shares, PyAttributeSessionKeyShare, PyPseudonymSessionKeyShare,
    PySessionKeyShares, PySessionKeys, PySessionPublicKeys, PySessionSecretKeys,
};

use pyo3::prelude::*;

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    blinding::register(m)?;
    setup::register(m)?;
    shares::register(m)?;
    Ok(())
}
