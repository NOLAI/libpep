//! Python bindings for cryptographic factors, transcryption info, and the secrets they derive from.

pub mod derivation;
pub mod secrets;
pub mod types;

pub use derivation::{
    py_make_attribute_rekey_factor, py_make_pseudonym_rekey_factor, py_make_pseudonymisation_factor,
};
pub use secrets::{PyEncryptionSecret, PyPseudonymizationSecret};
pub use types::{
    PyAttributeRekeyFactor, PyAttributeRekeyInfo, PyPseudonymRekeyFactor, PyPseudonymRekeyInfo,
    PyPseudonymizationInfo, PyRerandomizeFactor, PyReshuffleFactor, PyTranscryptionInfo,
};

use pyo3::prelude::*;

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    types::register(m)?;
    secrets::register(m)?;
    derivation::register(m)?;
    Ok(())
}
