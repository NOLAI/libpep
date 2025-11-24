#[cfg(feature = "batch")]
pub mod batch;
pub mod contexts;
pub mod ops;
pub mod secrets;

#[cfg(feature = "batch")]
pub use batch::{py_pseudonymize_batch, py_rekey_batch, py_transcrypt_batch};
pub use contexts::{
    PyAttributeRekeyFactor, PyAttributeRekeyInfo, PyPseudonymRSKFactors, PyPseudonymRekeyFactor,
    PyPseudonymizationInfo, PyReshuffleFactor, PyTranscryptionInfo,
};
pub use ops::{
    py_decrypt_attribute, py_decrypt_pseudonym, py_encrypt_attribute, py_encrypt_pseudonym,
    py_pseudonymize, py_rekey_attribute, py_rekey_pseudonym, py_transcrypt_attribute,
    py_transcrypt_pseudonym,
};
pub use secrets::{
    py_make_attribute_rekey_factor, py_make_pseudonym_rekey_factor, py_make_pseudonymisation_factor,
};

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(feature = "batch")]
    batch::register(m)?;
    contexts::register(m)?;
    ops::register(m)?;
    secrets::register(m)?;
    Ok(())
}
