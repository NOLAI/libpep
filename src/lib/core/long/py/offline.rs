use super::data::{
    PyLongAttribute, PyLongEncryptedAttribute, PyLongEncryptedPseudonym, PyLongPseudonym,
};
use crate::arithmetic::group_elements::GroupElement;
use crate::core::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(feature = "insecure")]
use crate::core::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::core::py::keys::{PyAttributeGlobalPublicKey, PyPseudonymGlobalPublicKey};
#[cfg(feature = "insecure")]
use crate::core::py::keys::{PyAttributeGlobalSecretKey, PyPseudonymGlobalSecretKey};
use pyo3::prelude::*;

/// Encrypt a long pseudonym using a global pseudonym public key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
#[pyfunction]
#[pyo3(name = "encrypt_long_pseudonym_global")]
pub fn py_encrypt_long_pseudonym_global(
    message: &PyLongPseudonym,
    public_key: &PyPseudonymGlobalPublicKey,
) -> PyLongEncryptedPseudonym {
    let mut rng = rand::rng();
    PyLongEncryptedPseudonym(crate::core::long::offline::encrypt_long_pseudonym_global(
        &message.0,
        &PseudonymGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Encrypt a long attribute using a global attribute public key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
#[pyfunction]
#[pyo3(name = "encrypt_long_attribute_global")]
pub fn py_encrypt_long_attribute_global(
    message: &PyLongAttribute,
    public_key: &PyAttributeGlobalPublicKey,
) -> PyLongEncryptedAttribute {
    let mut rng = rand::rng();
    PyLongEncryptedAttribute(crate::core::long::offline::encrypt_long_attribute_global(
        &message.0,
        &AttributeGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Decrypt a long encrypted pseudonym using a global pseudonym secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_long_pseudonym_global")]
pub fn py_decrypt_long_pseudonym_global(
    encrypted: &PyLongEncryptedPseudonym,
    secret_key: &PyPseudonymGlobalSecretKey,
) -> Option<PyLongPseudonym> {
    crate::core::long::offline::decrypt_long_pseudonym_global(
        &encrypted.0,
        &PseudonymGlobalSecretKey::from(secret_key.0 .0),
    )
    .map(PyLongPseudonym)
}

/// Decrypt a long encrypted pseudonym using a global pseudonym secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "decrypt_long_pseudonym_global")]
pub fn py_decrypt_long_pseudonym_global(
    encrypted: &PyLongEncryptedPseudonym,
    secret_key: &PyPseudonymGlobalSecretKey,
) -> PyLongPseudonym {
    PyLongPseudonym(crate::core::long::offline::decrypt_long_pseudonym_global(
        &encrypted.0,
        &PseudonymGlobalSecretKey::from(secret_key.0 .0),
    ))
}

/// Decrypt a long encrypted attribute using a global attribute secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_long_attribute_global")]
pub fn py_decrypt_long_attribute_global(
    encrypted: &PyLongEncryptedAttribute,
    secret_key: &PyAttributeGlobalSecretKey,
) -> Option<PyLongAttribute> {
    crate::core::long::offline::decrypt_long_attribute_global(
        &encrypted.0,
        &AttributeGlobalSecretKey::from(secret_key.0 .0),
    )
    .map(PyLongAttribute)
}

/// Decrypt a long encrypted attribute using a global attribute secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "decrypt_long_attribute_global")]
pub fn py_decrypt_long_attribute_global(
    encrypted: &PyLongEncryptedAttribute,
    secret_key: &PyAttributeGlobalSecretKey,
) -> PyLongAttribute {
    PyLongAttribute(crate::core::long::offline::decrypt_long_attribute_global(
        &encrypted.0,
        &AttributeGlobalSecretKey::from(secret_key.0 .0),
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_encrypt_long_pseudonym_global, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_long_attribute_global, m)?)?;
    #[cfg(feature = "insecure")]
    m.add_function(wrap_pyfunction!(py_decrypt_long_pseudonym_global, m)?)?;
    #[cfg(feature = "insecure")]
    m.add_function(wrap_pyfunction!(py_decrypt_long_attribute_global, m)?)?;
    Ok(())
}
