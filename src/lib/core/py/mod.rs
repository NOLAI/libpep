#[allow(clippy::wrong_self_convention)]
pub mod core;
#[cfg(feature = "global")]
pub mod global;
#[allow(clippy::wrong_self_convention)]
pub mod keys;
pub mod padding;
pub mod rerandomize;

pub use core::{PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym};
#[cfg(all(feature = "global", feature = "insecure"))]
pub use global::{py_decrypt_attribute_global, py_decrypt_pseudonym_global};
#[cfg(feature = "global")]
pub use global::{py_encrypt_attribute_global, py_encrypt_pseudonym_global};
pub use keys::{
    PyAttributeGlobalKeyPair, PyAttributeGlobalPublicKey, PyAttributeGlobalSecretKey,
    PyAttributeSessionKeyPair, PyAttributeSessionPublicKey, PyAttributeSessionSecretKey,
    PyEncryptionSecret, PyGlobalPublicKeys, PyGlobalSecretKeys, PyPseudonymGlobalKeyPair,
    PyPseudonymGlobalPublicKey, PyPseudonymGlobalSecretKey, PyPseudonymSessionKeyPair,
    PyPseudonymSessionPublicKey, PyPseudonymSessionSecretKey, PyPseudonymizationSecret,
};
pub use rerandomize::{
    py_rerandomize_encrypted_attribute, py_rerandomize_encrypted_attribute_known,
    py_rerandomize_encrypted_pseudonym, py_rerandomize_encrypted_pseudonym_known,
};

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    core::register(m)?;
    keys::register(m)?;
    #[cfg(feature = "global")]
    global::register(m)?;
    padding::register(m)?;
    rerandomize::register(m)?;
    super::transcryption::py::register_module(m)?;
    #[cfg(feature = "long")]
    super::long::py::register_module(m)?;
    Ok(())
}
