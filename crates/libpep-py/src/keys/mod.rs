pub mod distribution;
pub mod generation;
pub mod types;

// Re-export types for backwards compatibility and easier imports
pub use distribution::{
    PyAttributeSessionKeyShare, PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalKeys,
    PyBlindedPseudonymGlobalSecretKey, PyBlindingFactor, PyPseudonymSessionKeyShare,
    PySessionKeyShares, PySessionPublicKeys, PySessionSecretKeys,
};
pub use types::{
    PyAttributeGlobalPublicKey, PyAttributeGlobalSecretKey, PyAttributeSessionPublicKey,
    PyAttributeSessionSecretKey, PyEncryptionSecret, PyGlobalPublicKeys, PyGlobalSecretKeys,
    PyPseudonymGlobalPublicKey, PyPseudonymGlobalSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey, PyPseudonymizationSecret, PySessionKeys,
};

use pyo3::prelude::*;

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    types::register(m)?;
    generation::register(m)?;
    distribution::register(m)?;
    Ok(())
}
