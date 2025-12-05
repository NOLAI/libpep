use super::super::keys::{AttributeGlobalPublicKey, PseudonymGlobalPublicKey};
#[cfg(feature = "insecure")]
use super::super::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
#[cfg(feature = "insecure")]
use super::super::offline::{decrypt_attribute_global, decrypt_pseudonym_global};
use super::super::offline::{encrypt_attribute_global, encrypt_pseudonym_global};
use super::data::{PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym};
use super::keys::{PyAttributeGlobalPublicKey, PyPseudonymGlobalPublicKey};
#[cfg(feature = "insecure")]
use super::keys::{PyAttributeGlobalSecretKey, PyPseudonymGlobalSecretKey};
use crate::arithmetic::group_elements::GroupElement;
use pyo3::prelude::*;

/// Encrypt a pseudonym using a global pseudonym public key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
#[pyfunction]
#[pyo3(name = "encrypt_pseudonym_global")]
pub fn py_encrypt_pseudonym_global(
    m: &PyPseudonym,
    public_key: &PyPseudonymGlobalPublicKey,
) -> PyEncryptedPseudonym {
    let mut rng = rand::rng();
    encrypt_pseudonym_global(
        &m.0,
        &PseudonymGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    )
    .into()
}

/// Encrypt an attribute using a global attribute public key.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
#[pyfunction]
#[pyo3(name = "encrypt_attribute_global")]
pub fn py_encrypt_attribute_global(
    m: &PyAttribute,
    public_key: &PyAttributeGlobalPublicKey,
) -> PyEncryptedAttribute {
    let mut rng = rand::rng();
    encrypt_attribute_global(
        &m.0,
        &AttributeGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    )
    .into()
}

/// Decrypt a pseudonym that was encrypted with a global pseudonym public key,
/// using the global pseudonym secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_pseudonym_global")]
pub fn py_decrypt_pseudonym_global(
    v: &PyEncryptedPseudonym,
    secret_key: &PyPseudonymGlobalSecretKey,
) -> Option<PyPseudonym> {
    decrypt_pseudonym_global(&v.0, &PseudonymGlobalSecretKey::from(secret_key.0 .0))
        .map(|x| x.into())
}

/// Decrypt a pseudonym that was encrypted with a global pseudonym public key,
/// using the global pseudonym secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "decrypt_pseudonym_global")]
pub fn py_decrypt_pseudonym_global(
    v: &PyEncryptedPseudonym,
    secret_key: &PyPseudonymGlobalSecretKey,
) -> PyPseudonym {
    decrypt_pseudonym_global(&v.0, &PseudonymGlobalSecretKey::from(secret_key.0 .0)).into()
}

/// Decrypt an attribute that was encrypted with a global attribute public key,
/// using the global attribute secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_attribute_global")]
pub fn py_decrypt_attribute_global(
    v: &PyEncryptedAttribute,
    secret_key: &PyAttributeGlobalSecretKey,
) -> Option<PyAttribute> {
    decrypt_attribute_global(&v.0, &AttributeGlobalSecretKey::from(secret_key.0 .0))
        .map(|x| x.into())
}

/// Decrypt an attribute that was encrypted with a global attribute public key,
/// using the global attribute secret key.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "decrypt_attribute_global")]
pub fn py_decrypt_attribute_global(
    v: &PyEncryptedAttribute,
    secret_key: &PyAttributeGlobalSecretKey,
) -> PyAttribute {
    decrypt_attribute_global(&v.0, &AttributeGlobalSecretKey::from(secret_key.0 .0)).into()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_encrypt_pseudonym_global, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_attribute_global, m)?)?;
    #[cfg(feature = "insecure")]
    m.add_function(wrap_pyfunction!(py_decrypt_pseudonym_global, m)?)?;
    #[cfg(feature = "insecure")]
    m.add_function(wrap_pyfunction!(py_decrypt_attribute_global, m)?)?;
    Ok(())
}
