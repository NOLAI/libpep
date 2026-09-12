use crate::elgamal::arithmetic::group_elements::PyGroupElement;
use crate::elgamal::PyElGamal;
use crate::macros::{py_encrypted_impl, py_plaintext_impl};
use derive_more::{Deref, From, Into};
use libpep::data::padding::Padded;
use libpep::data::simple::*;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A pseudonym that can be used to identify a user
/// within a specific domain, which can be encrypted, rekeyed and reshuffled.
#[pyclass(name = "Pseudonym", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyPseudonym(pub(crate) Pseudonym);
py_plaintext_impl!(PyPseudonym wraps Pseudonym as "Pseudonym");

/// An attribute which should not be identifiable
/// within a specific domain, which can be encrypted and rekeyed, but not reshuffled.
#[pyclass(name = "Attribute", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyAttribute(pub(crate) Attribute);
py_plaintext_impl!(PyAttribute wraps Attribute as "Attribute");

/// An encrypted pseudonym, which is an [`PyElGamal`] encryption of a [`PyPseudonym`].
#[pyclass(name = "EncryptedPseudonym", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyEncryptedPseudonym(pub(crate) EncryptedPseudonym);
py_encrypted_impl!(PyEncryptedPseudonym wraps EncryptedPseudonym as "EncryptedPseudonym");

/// An encrypted attribute, which is an [`PyElGamal`] encryption of a [`PyAttribute`].
#[pyclass(name = "EncryptedAttribute", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyEncryptedAttribute(pub(crate) EncryptedAttribute);
py_encrypted_impl!(PyEncryptedAttribute wraps EncryptedAttribute as "EncryptedAttribute");

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPseudonym>()?;
    m.add_class::<PyAttribute>()?;
    m.add_class::<PyEncryptedPseudonym>()?;
    m.add_class::<PyEncryptedAttribute>()?;
    Ok(())
}
