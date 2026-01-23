pub mod distribution;
pub mod shares;
pub mod types;

// Re-export types for backwards compatibility and easier imports
pub use distribution::{
    PyBlindedAttributeGlobalSecretKey, PyBlindedGlobalKeys, PyBlindedPseudonymGlobalSecretKey,
    PyBlindingFactor,
};
pub use shares::{
    PyAttributeSessionKeyShare, PyPseudonymSessionKeyShare, PySessionKeyShares, PySessionKeys,
    PySessionPublicKeys, PySessionSecretKeys,
};
pub use types::{
    PyAttributeGlobalPublicKey, PyAttributeGlobalSecretKey, PyAttributeSessionPublicKey,
    PyAttributeSessionSecretKey, PyEncryptionSecret, PyGlobalPublicKeys, PyGlobalSecretKeys,
    PyPseudonymGlobalPublicKey, PyPseudonymGlobalSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey, PyPseudonymizationSecret,
};

use pyo3::prelude::*;

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    types::register(m)?;
    shares::register(m)?;
    distribution::register(m)?;
    Ok(())
}
