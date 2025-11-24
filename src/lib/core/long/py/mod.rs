pub mod batch;
pub mod data;
#[cfg(feature = "global")]
pub mod global;
pub mod ops;

pub use batch::{
    py_pseudonymize_long_batch, py_rekey_long_attribute_batch, py_rekey_long_pseudonym_batch,
    py_transcrypt_long_batch,
};
pub use data::{
    py_decrypt_long_attribute, py_decrypt_long_pseudonym, py_encrypt_long_attribute,
    py_encrypt_long_pseudonym, PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym,
    PyLongPseudonym,
};
#[cfg(all(feature = "global", feature = "insecure"))]
pub use global::{py_decrypt_long_attribute_global, py_decrypt_long_pseudonym_global};
#[cfg(feature = "global")]
pub use global::{py_encrypt_long_attribute_global, py_encrypt_long_pseudonym_global};
pub use ops::{
    py_pseudonymize_long, py_rekey_long_attribute, py_rekey_long_pseudonym,
    py_rerandomize_long_attribute, py_rerandomize_long_pseudonym, py_transcrypt_long_attribute,
    py_transcrypt_long_pseudonym,
};

use pyo3::prelude::*;

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    batch::register(m)?;
    data::register(m)?;
    #[cfg(feature = "global")]
    global::register(m)?;
    ops::register(m)?;
    Ok(())
}
