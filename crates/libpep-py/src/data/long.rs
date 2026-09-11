use crate::data::simple::{PyAttribute, PyEncryptedAttribute, PyEncryptedPseudonym, PyPseudonym};
use crate::keys::types::{
    PyAttributeSessionPublicKey, PyAttributeSessionSecretKey, PyPseudonymSessionPublicKey,
    PyPseudonymSessionSecretKey,
};
use crate::macros::{py_long_encrypted_impl, py_long_plaintext_impl};
use derive_more::{Deref, From};
use libpep::client::{decrypt, encrypt};
use libpep::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use libpep::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use libpep::keys::types::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey,
};
use libpep::keys::ElGamalPublicKey;
use libpep::keys::ElGamalSecretKey;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A collection of pseudonyms that together represent a larger pseudonym value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// The length (number of blocks) of a `LongPseudonym` may reveal information about the original data.
/// Consider padding your data to a fixed size before encoding to prevent length-based information leakage.
#[pyclass(name = "LongPseudonym", from_py_object)]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongPseudonym(pub(crate) LongPseudonym);

py_long_plaintext_impl!(PyLongPseudonym wraps LongPseudonym of PyPseudonym(Pseudonym) as "LongPseudonym",
    ctor(pseudonyms, doc = "Create from a vector of pseudonyms."),
    items(pseudonyms, doc = "Get the underlying pseudonyms."));

/// A collection of attributes that together represent a larger data value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// The length (number of blocks) of a `LongAttribute` may reveal information about the original data.
/// Consider padding your data to a fixed size before encoding to prevent length-based information leakage.
#[pyclass(name = "LongAttribute", from_py_object)]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongAttribute(pub(crate) LongAttribute);

py_long_plaintext_impl!(PyLongAttribute wraps LongAttribute of PyAttribute(Attribute) as "LongAttribute",
    ctor(attributes, doc = "Create from a vector of attributes."),
    items(attributes, doc = "Get the underlying attributes."));

/// A collection of encrypted pseudonyms that can be serialized as a pipe-delimited string.
#[pyclass(name = "LongEncryptedPseudonym", from_py_object)]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongEncryptedPseudonym(pub(crate) LongEncryptedPseudonym);

py_long_encrypted_impl!(PyLongEncryptedPseudonym wraps LongEncryptedPseudonym of PyEncryptedPseudonym(EncryptedPseudonym) as "LongEncryptedPseudonym",
    ctor(encrypted_pseudonyms, doc = "Create from a vector of encrypted pseudonyms."),
    items(encrypted_pseudonyms, doc = "Get the underlying encrypted pseudonyms."));

/// A collection of encrypted attributes that can be serialized as a pipe-delimited string.
#[pyclass(name = "LongEncryptedAttribute", from_py_object)]
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
pub struct PyLongEncryptedAttribute(pub(crate) LongEncryptedAttribute);

py_long_encrypted_impl!(PyLongEncryptedAttribute wraps LongEncryptedAttribute of PyEncryptedAttribute(EncryptedAttribute) as "LongEncryptedAttribute",
    ctor(encrypted_attributes, doc = "Create from a vector of encrypted attributes."),
    items(encrypted_attributes, doc = "Get the underlying encrypted attributes."));

/// Encrypt a long pseudonym.
#[pyfunction]
#[pyo3(name = "encrypt_long_pseudonym")]
pub fn py_encrypt_long_pseudonym(
    message: &PyLongPseudonym,
    public_key: &PyPseudonymSessionPublicKey,
) -> PyLongEncryptedPseudonym {
    let mut rng = rand::rng();
    PyLongEncryptedPseudonym(encrypt(
        &message.0,
        &PseudonymSessionPublicKey::from_point(*public_key.0),
        &mut rng,
    ))
}

/// Decrypt a long encrypted pseudonym.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_long_pseudonym")]
pub fn py_decrypt_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
    secret_key: &PyPseudonymSessionSecretKey,
) -> Option<PyLongPseudonym> {
    decrypt(
        &encrypted.0,
        &PseudonymSessionSecretKey::from_scalar(*secret_key.0),
    )
    .map(PyLongPseudonym)
}

/// Decrypt a long encrypted pseudonym.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_long_pseudonym")]
pub fn py_decrypt_long_pseudonym(
    encrypted: &PyLongEncryptedPseudonym,
    secret_key: &PyPseudonymSessionSecretKey,
) -> PyLongPseudonym {
    PyLongPseudonym(decrypt(
        &encrypted.0,
        &PseudonymSessionSecretKey::from_scalar(*secret_key.0),
    ))
}

/// Encrypt a long attribute.
#[pyfunction]
#[pyo3(name = "encrypt_long_attribute")]
pub fn py_encrypt_long_attribute(
    message: &PyLongAttribute,
    public_key: &PyAttributeSessionPublicKey,
) -> PyLongEncryptedAttribute {
    let mut rng = rand::rng();
    PyLongEncryptedAttribute(encrypt(
        &message.0,
        &AttributeSessionPublicKey::from_point(*public_key.0),
        &mut rng,
    ))
}

/// Decrypt a long encrypted attribute.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "decrypt_long_attribute")]
pub fn py_decrypt_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
    secret_key: &PyAttributeSessionSecretKey,
) -> Option<PyLongAttribute> {
    decrypt(
        &encrypted.0,
        &AttributeSessionSecretKey::from_scalar(*secret_key.0),
    )
    .map(PyLongAttribute)
}

/// Decrypt a long encrypted attribute.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "decrypt_long_attribute")]
pub fn py_decrypt_long_attribute(
    encrypted: &PyLongEncryptedAttribute,
    secret_key: &PyAttributeSessionSecretKey,
) -> PyLongAttribute {
    PyLongAttribute(decrypt(
        &encrypted.0,
        &AttributeSessionSecretKey::from_scalar(*secret_key.0),
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register types only
    m.add_class::<PyLongPseudonym>()?;
    m.add_class::<PyLongAttribute>()?;
    m.add_class::<PyLongEncryptedPseudonym>()?;
    m.add_class::<PyLongEncryptedAttribute>()?;

    Ok(())
}
