pub mod distribution;
pub mod generation;
pub mod types;

pub use distribution::{
    PyAttributeSessionKeyShare, PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalKeys,
    PyBlindedPseudonymGlobalSecretKey, PyBlindingFactor, PyPseudonymSessionKeyShare,
    PySessionKeyShares, PySessionPublicKeys, PySessionSecretKeys,
};
pub use types::{
    PyAttributeGlobalPublicKey, PyAttributeGlobalSecretKey, PyAttributeSessionPublicKey,
    PyAttributeSessionSecretKey, PyGlobalPublicKeys, PyGlobalSecretKeys,
    PyPseudonymGlobalPublicKey, PyPseudonymGlobalSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey, PySessionKeys,
};

use pyo3::prelude::*;

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    types::register(m)?;
    generation::register(m)?;
    distribution::register(m)?;
    Ok(())
}
